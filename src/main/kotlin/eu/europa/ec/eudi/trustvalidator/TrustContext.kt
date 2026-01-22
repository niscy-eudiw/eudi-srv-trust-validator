/*
 * Copyright (c) 2025-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.trustvalidator

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.eygraber.uri.Url
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.adapter.out.trust.KeyStoreManager
import eu.europa.ec.eudi.trustvalidator.adapter.out.trust.ListOfTrustedListsManager
import eu.europa.ec.eudi.trustvalidator.adapter.out.trust.TrustSourceManager
import eu.europa.ec.eudi.trustvalidator.adapter.out.trust.plus
import eu.europa.ec.eudi.trustvalidator.domain.*
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrusted
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.DefaultResourceLoader
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource

private val log = LoggerFactory.getLogger(TrustApplication::class.java)

@OptIn(ExperimentalSerializationApi::class)
internal fun beans(clock: Clock) = BeanRegistrarDsl {
    registerBean { clock }

    registerBean {
        val trustSources = env.getTrustSources()
        val keyStores = trustSources.filterIsInstance<TrustSource.KeyStore>().toNonEmptyListOrNull()
        val listsOfTrustedLists = trustSources.filterIsInstance<TrustSource.ListOfTrustedLists>().toNonEmptyListOrNull()

        val keyStoreManager = keyStores?.let { KeyStoreManager(it) }
        val listOfTrustedListsManager = listsOfTrustedLists?.let { ListOfTrustedListsManager(it, bean()) }

        val manager = listOfNotNull(listOfTrustedListsManager, keyStoreManager).reduceOrNull(TrustSourceManager::plus)
        checkNotNull(manager) { "No TrustSources configured" }
    }

    // VerifyTrust service
    registerBean { IsChainTrusted(bean()) }

    //
    // End points
    //
    registerBean {
        val trustApi = TrustApi(bean())
        val swaggerUi = SwaggerUi(
            publicResourcesBasePath =
                env.getRequiredProperty("spring.webflux.static-path-pattern").removeSuffix("/**"),
            webJarResourcesBasePath =
                env.getRequiredProperty("spring.webflux.webjars-path-pattern").removeSuffix("/**"),
        )
        trustApi.route.and(swaggerUi.route)
    }

    //
    // Other
    //
    registerBean {
        CodecCustomizer {
            val json = Json {
                explicitNulls = false
                ignoreUnknownKeys = true
            }

            it.defaultCodecs().kotlinSerializationJsonDecoder(KotlinSerializationJsonDecoder(json))
            it.defaultCodecs().kotlinSerializationJsonEncoder(KotlinSerializationJsonEncoder(json))
            it.defaultCodecs().enableLoggingRequestDetails(true)
        }
    }

    registerBean {
        val http = bean<ServerHttpSecurity>()
        http {
            cors { // cross-origin resource sharing configuration
                configurationSource = CorsConfigurationSource {
                    CorsConfiguration().apply {
                        fun getOptionalList(name: String): NonEmptyList<String>? =
                            env.getOptionalList(name = name, filter = { it.isNotBlank() }, transform = { it.trim() })

                        allowedOrigins = getOptionalList("cors.origins")
                        allowedOriginPatterns = getOptionalList("cors.originPatterns")
                        allowedMethods = getOptionalList("cors.methods")
                        run {
                            val headers = getOptionalList("cors.headers")
                            allowedHeaders = headers
                            exposedHeaders = headers
                        }
                        allowCredentials = env.getProperty<Boolean>("cors.credentials")
                        maxAge = env.getProperty<Long>("cors.maxAge")
                    }
                }
            }
            csrf { disable() } // cross-site request forgery disabled
        }
    }
}

private enum class TrustSourceType {
    KeyStore,
    LOTL,
    LOTE,
}

private fun Environment.getTrustSources(): List<TrustSource> = buildList {
    var index = 0

    while (true) {
        val prefix = "trustSources[$index]"

        val trustSourceType = getPropertyOrEnvVariable<TrustSourceType>("$prefix.type")
        when (trustSourceType) {
            null -> break
            TrustSourceType.KeyStore -> add(getKeyStoreTrustSource(prefix))
            TrustSourceType.LOTL -> add(getListOfTrustedListsTrustSource(prefix))
            TrustSourceType.LOTE -> add(getListOfTrustedEntitiesTrustSource(prefix))
        }

        index++
    }
}

private fun Environment.getKeyStoreTrustSource(prefix: String): TrustSource.KeyStore {
    val entity = getRequiredPropertyOrEnvVariable<Entity>("$prefix.entity")
    val service = getRequiredPropertyOrEnvVariable<Service>("$prefix.service")
    val properties = checkNotNull(getKeyStoreProperties(prefix)) { "Missing KeyStore configuration for $prefix" }
    return TrustSource.KeyStore(entity, service, properties)
}

private fun Environment.getKeyStoreProperties(prefix: String): KeyStoreProperties? =
    getPropertyOrEnvVariable("$prefix.location")?.let {
        val location = DefaultResourceLoader().getResource(it)
        val type = getPropertyOrEnvVariable("$prefix.storeType", "JKS")
        val password = getPropertyOrEnvVariable("$prefix.password")?.takeIf { password -> password.isNotBlank() }
        KeyStoreProperties(location, type, password)
    }

private fun Environment.getListOfTrustedListsTrustSource(prefix: String): TrustSource.ListOfTrustedLists {
    val location = Url.parse(getRequiredPropertyOrEnvVariable("$prefix.location"))
    val signatureVerification = getKeyStoreProperties("$prefix.keyStore")
    return TrustSource.ListOfTrustedLists(location, signatureVerification)
}

private fun Environment.getListOfTrustedEntitiesTrustSource(prefix: String): TrustSource.ListOfTrustedEntities {
    val entity = getRequiredPropertyOrEnvVariable<Entity>("$prefix.entity")
    val location = Url.parse(getRequiredPropertyOrEnvVariable("$prefix.location"))
    val signatureVerification = getKeyStoreProperties("$prefix.keyStore")
    return TrustSource.ListOfTrustedEntities(entity, location, signatureVerification)
}

private fun Environment.getPropertyOrEnvVariable(property: String): String? =
    getProperty(property) ?: getProperty(toEnvironmentVariable(property))

private fun Environment.getPropertyOrEnvVariable(property: String, defaultValue: String): String =
    getProperty(property) ?: getProperty(toEnvironmentVariable(property)) ?: defaultValue

private inline fun <reified T> Environment.getPropertyOrEnvVariable(property: String): T? =
    getProperty(key = property) ?: getProperty(key = toEnvironmentVariable(property))

private inline fun <reified T> Environment.getRequiredPropertyOrEnvVariable(property: String): T =
    getProperty(key = property)
        ?: getProperty(key = toEnvironmentVariable(property))
        ?: throw IllegalArgumentException("Missing required property '$property'")

private fun toEnvironmentVariable(property: String): String {
    return property.replace(".", "_")
        .replace("[", "_")
        .replace("]", "")
        .replace("-", "")
        .uppercase()
}

/**
 * Gets the value of a property that contains a comma-separated list. A list is returned when it contains values.
 *
 * @receiver the configured Spring [Environment] from which to load the property
 * @param name the property to load
 * @param filter optional filter to apply to the list value
 * @param transform optional mapping to apply to the list values
 */
private fun Environment.getOptionalList(
    name: String,
    filter: (String) -> Boolean = { true },
    transform: (String) -> String = { it },
): NonEmptyList<String>? =
    this.getProperty(name)
        ?.split(",")
        ?.filter { filter(it) }
        ?.map { transform(it) }
        ?.toNonEmptyListOrNull()
