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

import arrow.fx.coroutines.parMap
import arrow.fx.coroutines.resourceScope
import eu.europa.ec.eudi.trustvalidator.domain.*
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.CertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.nio.file.Files
import java.security.cert.TrustAnchor
import java.util.*
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant
import kotlin.time.toJavaInstant

class ListOfTrustedListsManager(
    private val listsOfTrustedLists: List<TrustSource.ListOfTrustedLists>,
    private val clock: Clock,
) : TrustSourceManager {
    private val dispatcher = Dispatchers.IO.limitedParallelism(4, "ListOfTrustedListsManager")
    private val mutex = Mutex()
    private val data = mutableMapOf<TrustSource.ListOfTrustedLists, TrustedListsCertificateSource>()

    override suspend fun getTrustAnchors(entity: Entity, service: Service): Set<TrustAnchor> {
        val serviceType = serviceTypeOf(entity, service)

        return if (null == serviceType) emptySet()
        else mutex.withLock {
            data.filter { (trustSource, _) -> entity == trustSource.entity }
                .values
                .flatMap { it.getTrustAnchors(serviceType, clock.now()) }.toSet()
        }
    }

    override suspend fun refresh() {
        mutex.withLock {
            listsOfTrustedLists.groupBy { it.location to it.signatureVerification }
                .values
                .parMap(dispatcher) { listsOfTrustedLists ->
                    val lotlCertificates = refresh(listsOfTrustedLists.first())
                    listsOfTrustedLists.forEach { data[it] = lotlCertificates }
                }
        }
    }

    private suspend fun refresh(trustSource: TrustSource.ListOfTrustedLists): TrustedListsCertificateSource =
        resourceScope {
            val cache = install(
                { Files.createTempDirectory("lotl-cache-${trustSource.hashCode()}").toFile() },
                { directory, _ -> directory.deleteRecursively() },
            )

            val offlineLoader =
                FileCacheDataLoader().apply {
                    setCacheExpirationTime(24.hours.inWholeMilliseconds)
                    setFileCacheDirectory(cache)
                    dataLoader = IgnoreDataLoader()
                }

            val onlineLoader =
                FileCacheDataLoader().apply {
                    setCacheExpirationTime(24.hours.inWholeMilliseconds)
                    setFileCacheDirectory(cache)
                    dataLoader = CommonsDataLoader()
                }

            val cacheCleaner = CacheCleaner().apply {
                setCleanMemory(true)
                setCleanFileSystem(true)
                setDSSFileLoader(offlineLoader)
            }

            val lotlCertificates = TrustedListsCertificateSource()
            val job = TLValidationJob().apply {
                setListOfTrustedListSources(trustSource.toLOTLSource())
                setOfflineDataLoader(offlineLoader)
                setOnlineDataLoader(onlineLoader)
                setTrustedListCertificateSource(lotlCertificates)
                setSynchronizationStrategy(ExpirationAndSignatureCheckStrategy())
                setCacheCleaner(cacheCleaner)
            }

            withContext(dispatcher) {
                job.onlineRefresh()
            }

            lotlCertificates
        }

    private suspend fun TrustSource.ListOfTrustedLists.toLOTLSource(): LOTLSource =
        LOTLSource().apply {
            url = location.toString()
            signatureVerification?.toCertificateSource()?.let { certificateSource = it }
            isPivotSupport = true
            trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
            tlVersions = listOf(5, 6)
        }

    private suspend fun KeyStoreProperties.toCertificateSource(): CertificateSource =
        resourceScope {
            val inputStream = install(location.inputStream)
            withContext(dispatcher) {
                KeyStoreCertificateSource(inputStream, type, passwordOrEmpty.toCharArray())
            }
        }
}

private fun serviceTypeOf(entity: Entity, service: Service): String? =
    when (entity) {
        Entity.WalletProvider -> "http://uri.etsi.org/TrstSvc/Svctype/Provider/Wallet"
        Entity.PIDProvider -> "http://uri.etsi.org/Svc/Svctype/Provider/PID"
        Entity.QEAAProvider -> "http://uri.etsi.org/TrstSvc/Svctype/EAA/Q"
        Entity.PubEAAProvider -> "http://uri.etsi.org/TrstSvc/Svctype/EAA/Pub-EAA"
        Entity.EAAProvider -> "http://uri.etsi.org/TrstSvc/Svctype/EAA"
        Entity.WalletRelyingPartyAccessCertificateProvider -> "http://uri.etsi.org/Svc/Svctype/CA/RPaccess"
        Entity.WalletRelyingPartyRegistrationCertificateProvider -> null
    }

private fun TrustedListsCertificateSource.getTrustAnchors(serviceType: String, at: Instant): List<TrustAnchor> =
    certificates.filter { certificate ->
        val trustServices = getTrustServices(certificate)
        trustServices.any {
            val activeTrustService = it.trustService.getCurrent(Date.from(at.toJavaInstant()))
            serviceType == activeTrustService?.type
        }
    }.map { TrustAnchor(it.certificate, null) }
