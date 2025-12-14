/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package uploader

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/apache/answer/internal/service/file_record"

	"github.com/apache/answer/internal/base/constant"
	"github.com/apache/answer/internal/base/reason"
	"github.com/apache/answer/internal/service/service_config"
	"github.com/apache/answer/internal/service/siteinfo_common"
	"github.com/apache/answer/pkg/checker"
	"github.com/apache/answer/pkg/dir"
	"github.com/apache/answer/pkg/uid"
	"github.com/apache/answer/plugin"
	"github.com/disintegration/imaging"
	"github.com/gin-gonic/gin"
	exifremove "github.com/scottleedavis/go-exif-remove"
	"github.com/segmentfault/pacman/errors"
	"github.com/segmentfault/pacman/log"
)

var (
	subPathList = []string{
		constant.AvatarSubPath,
		constant.AvatarThumbSubPath,
		constant.PostSubPath,
		constant.BrandingSubPath,
		constant.FilesPostSubPath,
		constant.DeletedSubPath,
	}
	supportedThumbFileExtMapping = map[string]imaging.Format{
		".jpg":  imaging.JPEG,
		".jpeg": imaging.JPEG,
		".png":  imaging.PNG,
		".gif":  imaging.GIF,
	}
)

type UploaderService interface {
	UploadAvatarFile(ctx *gin.Context, userID string) (url string, err error)
	UploadPostFile(ctx *gin.Context, userID string) (url string, err error)
	UploadPostAttachment(ctx *gin.Context, userID string) (url string, err error)
	UploadBrandingFile(ctx *gin.Context, userID string) (url string, err error)
	AvatarThumbFile(ctx *gin.Context, fileName string, size int) (url string, err error)
}

// uploaderService uploader service
type uploaderService struct {
	serviceConfig     *service_config.ServiceConfig
	siteInfoService   siteinfo_common.SiteInfoCommonService
	fileRecordService *file_record.FileRecordService
}

// NewUploaderService new upload service
func NewUploaderService(
	serviceConfig *service_config.ServiceConfig,
	siteInfoService siteinfo_common.SiteInfoCommonService,
	fileRecordService *file_record.FileRecordService,
) UploaderService {
	for _, subPath := range subPathList {
		err := dir.CreateDirIfNotExist(filepath.Join(serviceConfig.UploadPath, subPath))
		if err != nil {
			panic(err)
		}
	}
	return &uploaderService{
		serviceConfig:     serviceConfig,
		siteInfoService:   siteInfoService,
		fileRecordService: fileRecordService,
	}
}

// UploadAvatarFile upload avatar file
func (us *uploaderService) UploadAvatarFile(ctx *gin.Context, userID string) (url string, err error) {
	url, err = us.tryToUploadByPlugin(ctx, plugin.UserAvatar)
	if err != nil {
		return "", err
	}
	if len(url) > 0 {
		return url, nil
	}

	siteWrite, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}

	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, siteWrite.GetMaxImageSize())
	file, fileHeader, err := ctx.Request.FormFile("file")
	if err != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}
	defer func() {
		_ = file.Close()
	}()
	fileExt := safeLowerExtFromClientFilename(fileHeader.Filename)
	if len(fileExt) == 0 {
		return "", errors.BadRequest(reason.RequestFormatError)
	}
	if _, ok := plugin.DefaultFileTypeCheckMapping[plugin.UserAvatar][fileExt]; !ok {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}

	newFilename := fmt.Sprintf("%s%s", uid.IDStr12(), fileExt)
	avatarFilePath := path.Join(constant.AvatarSubPath, newFilename)
	url, err = us.uploadImageFile(ctx, fileHeader, avatarFilePath)
	if err != nil {
		return "", err
	}
	us.fileRecordService.AddFileRecord(ctx, userID, avatarFilePath, url, string(plugin.UserAvatar))
	return url, nil
}

func (us *uploaderService) AvatarThumbFile(ctx *gin.Context, fileName string, size int) (url string, err error) {
	// fileName comes from request parameters; ensure it cannot contain path separators.
	if containsPathSeparator(fileName) {
		return "", errors.NotFound(reason.UnknownError)
	}
	fileName = filepath.Base(fileName)
	if fileName == "." || fileName == "" {
		return "", errors.NotFound(reason.UnknownError)
	}

	fileSuffix := strings.ToLower(filepath.Ext(fileName))
	if _, ok := supportedThumbFileExtMapping[fileSuffix]; !ok {
		// if file type is not supported, return original file
		originalPath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, path.Join(constant.AvatarSubPath, fileName))
		if jErr != nil {
			return "", errors.NotFound(reason.UnknownError)
		}
		return originalPath, nil
	}
	if size > 1024 {
		size = 1024
	}

	thumbFileName := fmt.Sprintf("%d_%d@%s", size, size, fileName)
	thumbFilePath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, path.Join(constant.AvatarThumbSubPath, thumbFileName))
	if jErr != nil {
		return "", errors.NotFound(reason.UnknownError)
	}
	_, err = os.ReadFile(thumbFilePath)
	if err == nil {
		return thumbFilePath, nil
	}
	filePath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, path.Join(constant.AvatarSubPath, fileName))
	if jErr != nil {
		return "", errors.NotFound(reason.UnknownError)
	}
	avatarFile, err := os.ReadFile(filePath)
	if err != nil {
		return "", errors.NotFound(reason.UnknownError).WithError(err)
	}
	reader := bytes.NewReader(avatarFile)
	img, err := imaging.Decode(reader)
	if err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}

	var buf bytes.Buffer
	newImage := imaging.Fill(img, size, size, imaging.Center, imaging.Linear)
	if err = imaging.Encode(&buf, newImage, supportedThumbFileExtMapping[fileSuffix]); err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}

	if err = dir.CreateDirIfNotExist(path.Join(us.serviceConfig.UploadPath, constant.AvatarThumbSubPath)); err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}

	avatarFilePath := path.Join(constant.AvatarThumbSubPath, thumbFileName)
	saveFilePath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, avatarFilePath)
	if jErr != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(jErr).WithStack()
	}
	out, err := os.Create(saveFilePath)
	if err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}
	defer func() {
		_ = out.Close()
	}()

	thumbReader := bytes.NewReader(buf.Bytes())
	if _, err = io.Copy(out, thumbReader); err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}
	return saveFilePath, nil
}

func (us *uploaderService) UploadPostFile(ctx *gin.Context, userID string) (
	url string, err error) {
	url, err = us.tryToUploadByPlugin(ctx, plugin.UserPost)
	if err != nil {
		return "", err
	}
	if len(url) > 0 {
		return url, nil
	}

	siteWrite, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}

	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, siteWrite.GetMaxImageSize())
	file, fileHeader, err := ctx.Request.FormFile("file")
	if err != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}
	defer func() {
		_ = file.Close()
	}()
	if checker.IsUnAuthorizedExtension(filepath.Base(fileHeader.Filename), siteWrite.AuthorizedImageExtensions) {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}

	fileExt := safeLowerExtFromClientFilename(fileHeader.Filename)
	if len(fileExt) == 0 {
		return "", errors.BadRequest(reason.RequestFormatError)
	}
	newFilename := fmt.Sprintf("%s%s", uid.IDStr12(), fileExt)
	avatarFilePath := path.Join(constant.PostSubPath, newFilename)
	url, err = us.uploadImageFile(ctx, fileHeader, avatarFilePath)
	if err != nil {
		return "", err
	}
	us.fileRecordService.AddFileRecord(ctx, userID, avatarFilePath, url, string(plugin.UserPost))
	return url, nil
}

func (us *uploaderService) UploadPostAttachment(ctx *gin.Context, userID string) (
	url string, err error) {
	url, err = us.tryToUploadByPlugin(ctx, plugin.UserPostAttachment)
	if err != nil {
		return "", err
	}
	if len(url) > 0 {
		return url, nil
	}

	resp, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}

	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, resp.GetMaxAttachmentSize())
	file, fileHeader, err := ctx.Request.FormFile("file")
	if err != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}
	defer func() {
		_ = file.Close()
	}()
	originalFilename := filepath.Base(fileHeader.Filename)
	if checker.IsUnAuthorizedExtension(originalFilename, resp.AuthorizedAttachmentExtensions) {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}

	fileExt := safeLowerExtFromClientFilename(fileHeader.Filename)
	if len(fileExt) == 0 {
		return "", errors.BadRequest(reason.RequestFormatError)
	}
	newFilename := fmt.Sprintf("%s%s", uid.IDStr12(), fileExt)
	attachmentFilePath := path.Join(constant.FilesPostSubPath, newFilename)
	url, err = us.uploadAttachmentFile(ctx, fileHeader, originalFilename, attachmentFilePath)
	if err != nil {
		return "", err
	}
	us.fileRecordService.AddFileRecord(ctx, userID, attachmentFilePath, url, string(plugin.UserPostAttachment))
	return url, nil
}

func (us *uploaderService) UploadBrandingFile(ctx *gin.Context, userID string) (
	url string, err error) {
	url, err = us.tryToUploadByPlugin(ctx, plugin.AdminBranding)
	if err != nil {
		return "", err
	}
	if len(url) > 0 {
		return url, nil
	}

	siteWrite, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}

	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, siteWrite.GetMaxImageSize())
	file, fileHeader, err := ctx.Request.FormFile("file")
	if err != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}
	defer func() {
		_ = file.Close()
	}()
	fileExt := safeLowerExtFromClientFilename(fileHeader.Filename)
	if len(fileExt) == 0 {
		return "", errors.BadRequest(reason.RequestFormatError)
	}
	if _, ok := plugin.DefaultFileTypeCheckMapping[plugin.AdminBranding][fileExt]; !ok {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(err)
	}

	newFilename := fmt.Sprintf("%s%s", uid.IDStr12(), fileExt)
	avatarFilePath := path.Join(constant.BrandingSubPath, newFilename)
	url, err = us.uploadImageFile(ctx, fileHeader, avatarFilePath)
	if err != nil {
		return "", err
	}
	us.fileRecordService.AddFileRecord(ctx, userID, avatarFilePath, url, string(plugin.AdminBranding))
	return url, nil
}

func (us *uploaderService) uploadImageFile(ctx *gin.Context, file *multipart.FileHeader, fileSubPath string) (
	url string, err error) {
	siteGeneral, err := us.siteInfoService.GetSiteGeneral(ctx)
	if err != nil {
		return "", err
	}
	siteWrite, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}
	filePath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, fileSubPath)
	if jErr != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(jErr)
	}
	if err := ctx.SaveUploadedFile(file, filePath); err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}

	src, err := file.Open()
	if err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}
	defer func() {
		_ = src.Close()
	}()

	if !checker.DecodeAndCheckImageFile(filePath, siteWrite.GetMaxImageMegapixel()) {
		return "", errors.BadRequest(reason.UploadFileUnsupportedFileFormat)
	}

	if err := removeExif(filePath); err != nil {
		log.Error(err)
	}

	url = fmt.Sprintf("%s/uploads/%s", siteGeneral.SiteUrl, fileSubPath)
	return url, nil
}

func (us *uploaderService) uploadAttachmentFile(ctx *gin.Context, file *multipart.FileHeader, originalFilename, fileSubPath string) (
	downloadUrl string, err error) {
	siteGeneral, err := us.siteInfoService.GetSiteGeneral(ctx)
	if err != nil {
		return "", err
	}
	filePath, jErr := safeJoinUnderBase(us.serviceConfig.UploadPath, fileSubPath)
	if jErr != nil {
		return "", errors.BadRequest(reason.RequestFormatError).WithError(jErr)
	}
	if err := ctx.SaveUploadedFile(file, filePath); err != nil {
		return "", errors.InternalServer(reason.UnknownError).WithError(err).WithStack()
	}

	// Need url encode the original filename. Because the filename may contain special characters that conflict with the markdown syntax.
	originalFilename = url.QueryEscape(originalFilename)

	// The original filename is 123.pdf
	// The local saved path is /UploadPath/hash.pdf
	// When downloading, the download link will be redirect to the local saved path. And the download filename will be 123.png.
	downloadPath := strings.TrimSuffix(fileSubPath, filepath.Ext(fileSubPath)) + "/" + originalFilename
	downloadUrl = fmt.Sprintf("%s/uploads/%s", siteGeneral.SiteUrl, downloadPath)
	return downloadUrl, nil
}

func (us *uploaderService) tryToUploadByPlugin(ctx *gin.Context, source plugin.UploadSource) (
	url string, err error) {
	siteWrite, err := us.siteInfoService.GetSiteWrite(ctx)
	if err != nil {
		return "", err
	}
	cond := plugin.UploadFileCondition{
		Source:                         source,
		MaxImageSize:                   siteWrite.MaxImageSize,
		MaxAttachmentSize:              siteWrite.MaxAttachmentSize,
		MaxImageMegapixel:              siteWrite.MaxImageMegapixel,
		AuthorizedImageExtensions:      siteWrite.AuthorizedImageExtensions,
		AuthorizedAttachmentExtensions: siteWrite.AuthorizedAttachmentExtensions,
	}
	_ = plugin.CallStorage(func(fn plugin.Storage) error {
		resp := fn.UploadFile(ctx, cond)
		if resp.OriginalError != nil {
			log.Errorf("upload file by plugin failed, err: %v", resp.OriginalError)
			err = errors.BadRequest("").WithMsg(resp.DisplayErrorMsg.Translate(ctx)).WithError(err)
		} else {
			url = resp.FullURL
		}
		return nil
	})
	return url, err
}

// removeExif remove exif
// only support jpg/jpeg/png
func removeExif(path string) error {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
	if ext != "jpeg" && ext != "jpg" && ext != "png" {
		return nil
	}
	img, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	noExifBytes, err := exifremove.Remove(img)
	if err != nil {
		return err
	}
	return os.WriteFile(path, noExifBytes, 0644)
}

func safeLowerExtFromClientFilename(filename string) string {
	base := filepath.Base(filename)
	if base == "." || base == "" {
		return ""
	}
	return strings.ToLower(filepath.Ext(base))
}

func containsPathSeparator(s string) bool {
	return strings.Contains(s, "/") || strings.Contains(s, "\\")
}

// safeJoinUnderBase joins a (possibly slash-separated) subpath under baseDir and
// rejects path traversal / absolute paths.
func safeJoinUnderBase(baseDir, subPath string) (string, error) {
	if len(baseDir) == 0 {
		return "", fmt.Errorf("baseDir is empty")
	}
	if len(subPath) == 0 {
		return "", fmt.Errorf("subPath is empty")
	}
	if filepath.IsAbs(subPath) {
		return "", fmt.Errorf("absolute subPath is not allowed")
	}

	// fileSubPath values in this package use forward slashes; convert to OS separator.
	subPath = filepath.FromSlash(subPath)

	baseClean := filepath.Clean(baseDir)
	joined := filepath.Join(baseClean, filepath.Clean(subPath))

	baseAbs, err := filepath.Abs(baseClean)
	if err != nil {
		return "", err
	}
	joinedAbs, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(baseAbs, joinedAbs)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("path traversal detected")
	}
	return joined, nil
}
