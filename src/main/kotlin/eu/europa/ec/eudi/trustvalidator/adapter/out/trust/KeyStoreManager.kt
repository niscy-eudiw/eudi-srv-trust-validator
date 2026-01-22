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
package eu.europa.ec.eudi.trustvalidator.adapter.out.trust

import arrow.core.NonEmptyList
import arrow.fx.coroutines.parMap
import arrow.fx.coroutines.resourceScope
import eu.europa.ec.eudi.trustvalidator.domain.Entity
import eu.europa.ec.eudi.trustvalidator.domain.Service
import eu.europa.ec.eudi.trustvalidator.domain.TrustSource
import eu.europa.ec.eudi.trustvalidator.domain.passwordOrEmpty
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

class KeyStoreManager(
    private val keyStores: NonEmptyList<TrustSource.KeyStore>,
) : TrustSourceManager {
    private val dispatcher = Dispatchers.IO.limitedParallelism(4, "KeyStoreManager")
    private val mutex = Mutex()
    private val data = mutableMapOf<TrustSource.KeyStore, List<X509Certificate>>()

    override suspend fun getTrustAnchors(entity: Entity, service: Service): Set<TrustAnchor> =
        mutex.withLock {
            data.filter { (keyStore, _) -> entity == keyStore.entity && service == keyStore.service }
                .flatMap { (_, trustedCertificates) -> trustedCertificates.map { TrustAnchor(it, null) } }
                .toSet()
        }

    override suspend fun refresh() {
        mutex.withLock {
            keyStores.parMap(dispatcher) { keyStore ->
                val keyStoreCertificates = refresh(keyStore)
                data[keyStore] = keyStoreCertificates
            }
        }
    }

    private suspend fun refresh(trustSource: TrustSource.KeyStore): List<X509Certificate> =
        resourceScope {
            val keyStore = KeyStore.getInstance(trustSource.properties.type)
            val inputStream = install(trustSource.properties.location.inputStream)
            withContext(dispatcher) {
                keyStore.load(inputStream, trustSource.properties.passwordOrEmpty.toCharArray())
            }

            buildList {
                for (alias in keyStore.aliases()) {
                    if (keyStore.isCertificateEntry(alias)) {
                        add(keyStore.getCertificate(alias) as X509Certificate)
                    }
                }
            }
        }
}
