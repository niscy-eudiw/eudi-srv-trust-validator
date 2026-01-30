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
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrusted
import eu.europa.ec.eudi.etsi1196x2.consultation.IsChainTrustedForContext
import eu.europa.ec.eudi.etsi1196x2.consultation.ValidateCertificateChainJvm
import eu.europa.ec.eudi.etsi1196x2.consultation.VerificationContext
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.DSSAdapter
import eu.europa.ec.eudi.etsi1196x2.consultation.dss.usingLoTL
import eu.europa.ec.eudi.etsi1196x2.consultation.usingKeystore
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.SwaggerUi
import eu.europa.ec.eudi.trustvalidator.adapter.input.web.TrustApi
import eu.europa.ec.eudi.trustvalidator.domain.Clock
import eu.europa.ec.eudi.trustvalidator.domain.Clock.Companion.asKotlinClock
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType
import kotlinx.serialization.json.Json
import org.springframework.beans.factory.BeanRegistrarDsl
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.http.codec.CodecCustomizer
import org.springframework.core.env.Environment
import org.springframework.core.env.getProperty
import org.springframework.core.io.Resource
import org.springframework.http.codec.json.KotlinSerializationJsonDecoder
import org.springframework.http.codec.json.KotlinSerializationJsonEncoder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.reactive.CorsConfigurationSource
import java.net.URL
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.function.Predicate
import kotlin.time.toKotlinDuration
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrusted as IsChainTrustedUseCase

internal class Beans : BeanRegistrarDsl({
    registerBean { Clock.System }

    registerBean<IsChainTrustedForContext<List<X509Certificate>, TrustAnchor>> {
        val config = bean<TrustSourcesConfigurationProperties>()

        val usingLoTL = config.trustSources
            .filter { TrustSourceType.LOTL == it.type }
            .associate {
                val verificationContext = it.verificationContext()
                val lotlSource = it.lotlSource()
                verificationContext to lotlSource
            }.let {
                IsChainTrustedForContext.usingLoTL(
                    sourcePerVerification = it,
                    validateCertificateChain = ValidateCertificateChainJvm {
                        isRevocationEnabled = false
                    },
                    dssAdapter = DSSAdapter.usingFileCacheDataLoader(
                        cacheDirectory = Files.createTempDirectory("dss"),
                    ),
                    clock = bean<Clock>().asKotlinClock(),
                    ttl = config.timeToLive.toKotlinDuration(),
                )
            }

        val usingKeystore = config.trustSources
            .filter { TrustSourceType.KeyStore == it.type }
            .associate {
                val verificationContext = it.verificationContext()
                val isChainTrusted = IsChainTrusted.usingKeystore { loadKeyStore(checkNotNull(it.keyStore)) }
                verificationContext to isChainTrusted
            }
            .let { IsChainTrustedForContext(it) }

        usingLoTL.or(usingKeystore)
    }

    registerBean { IsChainTrustedUseCase(bean()) }

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
})

@Suppress("ConfigurationProperties")
@ConfigurationProperties
data class TrustSourcesConfigurationProperties(
    val trustSources: List<TrustSourceConfigurationProperties>,
    val timeToLive: Duration,
)

data class TrustSourceConfigurationProperties(
    val type: TrustSourceType,
    val verificationContext: VerificationContextOption,
    val useCase: String? = null,
    val keyStore: KeyStoreConfigurationProperties? = null,
    val location: URL? = null,
    val serviceTypes: List<String>? = null,
    val timeToLive: Duration? = null,
)

enum class TrustSourceType {
    KeyStore,
    LOTL,
    LOTE,
}

enum class VerificationContextOption {
    WalletInstanceAttestation,
    WalletUnitAttestation,
    WalletUnitAttestationStatus,
    PID,
    PIDStatus,
    PubEAA,
    PubEAAStatus,
    QEAA,
    QEAAStatus,
    EAA,
    EAAStatus,
    WalletRelyingPartyRegistrationCertificate,
    WalletRelyingPartyAccessCertificate,
    Custom,
}

private fun TrustSourceConfigurationProperties.verificationContext(): VerificationContext {
    fun useCase(): String = requireNotNull(useCase) { "useCase is required for verificationContext $verificationContext" }
    return when (verificationContext) {
        VerificationContextOption.WalletInstanceAttestation -> VerificationContext.WalletInstanceAttestation
        VerificationContextOption.WalletUnitAttestation -> VerificationContext.WalletUnitAttestation
        VerificationContextOption.WalletUnitAttestationStatus -> VerificationContext.WalletUnitAttestationStatus
        VerificationContextOption.PID -> VerificationContext.PID
        VerificationContextOption.PIDStatus -> VerificationContext.PIDStatus
        VerificationContextOption.PubEAA -> VerificationContext.PubEAA
        VerificationContextOption.PubEAAStatus -> VerificationContext.PubEAAStatus
        VerificationContextOption.QEAA -> VerificationContext.QEAA
        VerificationContextOption.QEAAStatus -> VerificationContext.QEAAStatus
        VerificationContextOption.EAA -> VerificationContext.EAA(useCase())
        VerificationContextOption.EAAStatus -> VerificationContext.EAAStatus(useCase())
        VerificationContextOption.WalletRelyingPartyRegistrationCertificate -> VerificationContext.WalletRelyingPartyRegistrationCertificate
        VerificationContextOption.WalletRelyingPartyAccessCertificate -> VerificationContext.WalletRelyingPartyAccessCertificate
        VerificationContextOption.Custom -> VerificationContext.Custom(useCase())
    }
}

data class KeyStoreConfigurationProperties(
    val location: Resource,
    val type: String = "JKS",
    val password: String? = null,
)

/**
 * Loads a KeyStore from a Resource.
 *
 * **This function is blocking.**
 */
private fun loadKeyStore(properties: KeyStoreConfigurationProperties): KeyStore =
    properties.location.inputStream.use {
        val keyStore = KeyStore.getInstance(properties.type)
        keyStore.load(it, (properties.password ?: "").toCharArray())
        keyStore
    }

/**
 * Gets a LOTLSource from this TrustSourceConfigurationProperties.
 *
 * **This function is blocking.**
 */
private fun TrustSourceConfigurationProperties.lotlSource(): LOTLSource =
    LOTLSource().apply {
        url = requireNotNull(location) { "location is required for ${TrustSourceType.LOTL} trust source" }.toExternalForm()

        // LOTL signature verification
        if (null != keyStore) {
            certificateSource = keyStore.location.inputStream.use {
                KeyStoreCertificateSource(it, keyStore.type, (keyStore.password ?: "").toCharArray())
            }
        }

        tlVersions = listOf(5, 6)

        isPivotSupport = true

        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()

        if (!serviceTypes.isNullOrEmpty()) {
            trustServicePredicate =
                serviceTypes.map { serviceType ->
                    Predicate<TSPServiceType> {
                        serviceType == it.serviceInformation.serviceTypeIdentifier
                    }
                }.reduce { accumulator, current -> accumulator.or(current) }
        }
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
