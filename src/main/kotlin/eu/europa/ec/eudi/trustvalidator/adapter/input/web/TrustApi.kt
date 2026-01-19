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
package eu.europa.ec.eudi.trustvalidator.adapter.input.web

import arrow.core.Either
import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.raise.either
import eu.europa.ec.eudi.trustvalidator.adapter.out.x5c.X509CertificateChainSerializer
import eu.europa.ec.eudi.trustvalidator.domain.ProviderType
import eu.europa.ec.eudi.trustvalidator.port.input.trust.VerifyTrust
import eu.europa.ec.eudi.trustvalidator.port.input.trust.VerifyTrustError
import kotlinx.serialization.Serializable
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import java.security.cert.X509Certificate

internal class TrustApi(
    private val verifyTrust: VerifyTrust,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        POST(
            TRUST_QUERY,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            ::trustQuery,
        )
    }

    private suspend fun trustQuery(request: ServerRequest): ServerResponse {
        @Serializable
        data class TrustQueryRequest(
            @Serializable(with = X509CertificateChainSerializer::class)
            val x5c: NonEmptyList<X509Certificate>,
            val serviceType: ProviderType,
        )

        @Serializable
        data class TrustQueryResponse(
            val trusted: Boolean,
        )

        @Serializable
        data class ErrorResponse(
            val error: String,
            val description: String,
        )

        return either {
            val body = Either.catch { request.awaitBody<TrustQueryRequest>() }
                .mapLeft {
                    ErrorResponse(
                        error = "Invalid request body",
                        description = it.message ?: "Unparsable request body",
                    )
                }
                .bind()
            val serviceType = body.serviceType.toDomain()
            val trusted = verifyTrust(serviceType, body.x5c)
                .mapLeft {
                    when (it) {
                        VerifyTrustError.UnknownServiceType ->
                            ErrorResponse(
                                error = "Unknown service type",
                                description = "Service type provided does not exist",
                            )
                    }
                }
                .bind()
            TrustQueryResponse(trusted)
        }.map { ok().json().bodyValueAndAwait(it) }
            .getOrElse { badRequest().json().bodyValueAndAwait(it) }
    }

    companion object {
        const val TRUST_QUERY = "/trust"
    }
}
