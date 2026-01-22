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

import arrow.core.NonEmptyList
import arrow.core.getOrElse
import arrow.core.raise.catch
import arrow.core.raise.either
import eu.europa.ec.eudi.trustvalidator.adapter.out.serialization.X509CertificateChainSerializer
import eu.europa.ec.eudi.trustvalidator.domain.VerificationCase
import eu.europa.ec.eudi.trustvalidator.port.input.trust.IsChainTrusted
import kotlinx.serialization.Serializable
import org.springframework.http.MediaType.APPLICATION_JSON
import org.springframework.web.reactive.function.server.*
import org.springframework.web.reactive.function.server.ServerResponse.badRequest
import org.springframework.web.reactive.function.server.ServerResponse.ok
import java.security.cert.X509Certificate

internal class TrustApi(
    private val isChainTrusted: IsChainTrusted,
) {
    val route: RouterFunction<ServerResponse> = coRouter {
        POST(
            TRUST_V2,
            contentType(APPLICATION_JSON) and accept(APPLICATION_JSON),
            ::trustQueryV2,
        )
    }

    private suspend fun trustQueryV2(request: ServerRequest): ServerResponse {
        @Serializable
        data class TrustQuery(
            @Serializable(with = X509CertificateChainSerializer::class) val chain: NonEmptyList<X509Certificate>,
            val case: VerificationCase,
        )

        @Serializable
        data class TrustResponse(val trusted: Boolean)

        @Serializable
        data class ErrorResponse(val description: String)

        return either {
            val query = catch({ request.awaitBody<TrustQuery>() }) { error ->
                val description = buildString {
                    append("Unparsable request body")
                    error.message?.let { append(": $it") }
                }
                raise(ErrorResponse(description))
            }
            val trusted = isChainTrusted(query.chain, query.case)
            ok().json().bodyValueAndAwait(TrustResponse(trusted))
        }.getOrElse { badRequest().json().bodyValueAndAwait(it) }
    }

    companion object {
        const val TRUST = "/trust"
        const val TRUST_V2 = "/v2/trust"
    }
}
