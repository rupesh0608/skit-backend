package com.rdktechnologies.skit.utils


import com.rdktechnologies.skit.error.exceptions.InvalidFileTypeException
import org.springframework.util.StringUtils
import org.springframework.web.multipart.MultipartFile

class FileHelper {
    fun getExtension(file: MultipartFile): String? {
        return StringUtils.getFilenameExtension(file.originalFilename)
    }

    fun getContentType(file: MultipartFile): String? {
        return if (file.contentType == "video/mp4") {
            "video"
        } else if (file.contentType == "image/jpeg" || file.contentType == "image/png" || file.contentType == "image/jpg") {
            "image"
        } else {
            val ext = getExtension(file)
            throw  InvalidFileTypeException("files with $ext not allowed")
        }

    }
}