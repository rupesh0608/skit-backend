package com.rdktechnologies.skit.error


import com.rdktechnologies.skit.dto.response.SimpleResponse
import org.springframework.beans.TypeMismatchException
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.validation.FieldError
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingServletRequestParameterException
import org.springframework.web.bind.annotation.ControllerAdvice
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.context.request.WebRequest
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler





@ControllerAdvice
class ExceptionHandler() : ResponseEntityExceptionHandler() {

    override fun handleMethodArgumentNotValid(ex: MethodArgumentNotValidException, headers: HttpHeaders, status: HttpStatus, request: WebRequest): ResponseEntity<Any> {
        ex.bindingResult.allErrors.forEach { error ->
           val fieldName = (error as FieldError).field
          var  message = error.defaultMessage.toString()
            message= "$fieldName $message"
            return ResponseEntity.ok(SimpleResponse(true, status.value(), message))
        }
        return ResponseEntity.ok(SimpleResponse(true, status.value(), ""))

    }

    override fun handleMissingServletRequestParameter(ex: MissingServletRequestParameterException, headers: HttpHeaders, status: HttpStatus, request: WebRequest): ResponseEntity<Any> {
            return ResponseEntity.ok(SimpleResponse(true, status.value(), ex.message))
    }

    override fun handleHttpMessageNotReadable(ex: HttpMessageNotReadableException, headers: HttpHeaders, status: HttpStatus, request: WebRequest): ResponseEntity<Any> {
        return ResponseEntity.ok(SimpleResponse(true, status.value(),"Requested body missing"))
    }

    override fun handleTypeMismatch(ex: TypeMismatchException, headers: HttpHeaders, status: HttpStatus, request: WebRequest): ResponseEntity<Any> {
        return ResponseEntity.ok(SimpleResponse(true, status.value(),ex.message))
    }
    @ExceptionHandler(Exception::class)
    protected fun exception(ex: Exception): ResponseEntity<SimpleResponse> {
        return ResponseEntity.ok(SimpleResponse(true, 404, ex.message))
    }


}