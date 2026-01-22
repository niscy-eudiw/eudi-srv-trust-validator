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
package eu.europa.ec.eudi.trustvalidator.domain

import com.eygraber.uri.Url
import org.springframework.core.io.Resource

enum class Entity {
    WalletProvider,
    PIDProvider,
    QEAAProvider,
    PubEAAProvider,
    EAAProvider,
    WalletRelyingPartyAccessCertificateProvider,
    WalletRelyingPartyRegistrationCertificateProvider,
}

enum class Service {
    Issuance,
    Revocation,
}

data class KeyStoreProperties(
    val location: Resource,
    val type: String,
    val password: String?,
) {
    init {
        require(location.exists() && location.isReadable)
    }
}

val KeyStoreProperties.passwordOrEmpty: String
    get() = password ?: ""

sealed interface TrustSource {

    data class KeyStore(
        val entity: Entity,
        val service: Service,
        val properties: KeyStoreProperties,
    ) : TrustSource

    data class ListOfTrustedLists(
        val location: Url,
        val signatureVerification: KeyStoreProperties?,
    ) : TrustSource

    data class ListOfTrustedEntities(
        val entity: Entity,
        val location: Url,
        val signatureVerification: KeyStoreProperties?,
    ) : TrustSource
}
