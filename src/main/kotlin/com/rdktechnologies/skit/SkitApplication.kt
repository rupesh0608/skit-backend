package com.rdktechnologies.skit

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Info
import org.springframework.boot.autoconfigure.EnableAutoConfiguration
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.data.jpa.repository.config.EnableJpaRepositories

@EnableJpaRepositories(basePackages = ["com.rdktechnologies.skit.repository"])
@SpringBootApplication
@EnableAutoConfiguration
@OpenAPIDefinition(info = Info(title = "skit", version = "1.0"))
class SkitApplication

fun main(args: Array<String>) {
	runApplication<SkitApplication>(*args)
}
