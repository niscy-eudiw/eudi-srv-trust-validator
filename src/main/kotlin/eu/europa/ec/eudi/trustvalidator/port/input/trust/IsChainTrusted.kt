/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.trustvalidator.port.input.trust

import arrow.core.NonEmptyList
import arrow.core.raise.result
import eu.europa.ec.eudi.trustvalidator.domain.VerificationCase
import eu.europa.ec.eudi.trustvalidator.port.out.trust.GetTrustAnchors
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate

fun interface IsChainTrusted {
    suspend operator fun invoke(chain: NonEmptyList<X509Certificate>, case: VerificationCase): Boolean
}

fun IsChainTrusted(getTrustAnchors: GetTrustAnchors): IsChainTrusted =
    object : IsChainTrusted {
        private val factory by lazy { CertificateFactory.getInstance("X.509") }
        private val validator by lazy { CertPathValidator.getInstance("PKIX") }

        override suspend fun invoke(
            chain: NonEmptyList<X509Certificate>,
            case: VerificationCase,
        ): Boolean =
            result {
                val path = factory.generateCertPath(chain)
                val trustAnchors = getTrustAnchors(case)
                val parameters = PKIXParameters(trustAnchors)
                    .apply {
                        isRevocationEnabled = false
                    }
                validator.validate(path, parameters)
                true
            }.getOrElse { false }
    }
