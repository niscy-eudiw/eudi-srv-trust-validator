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

import eu.europa.ec.eudi.trustvalidator.domain.Entity
import eu.europa.ec.eudi.trustvalidator.domain.Service
import eu.europa.ec.eudi.trustvalidator.domain.VerificationCase
import eu.europa.ec.eudi.trustvalidator.port.out.trust.GetTrustAnchors
import kotlinx.coroutines.runBlocking
import org.springframework.beans.factory.InitializingBean
import java.security.cert.TrustAnchor

interface TrustSourceManager : GetTrustAnchors, InitializingBean {

    suspend fun getTrustAnchors(entity: Entity, service: Service): Set<TrustAnchor>
    suspend fun refresh()

    override suspend fun invoke(case: VerificationCase): Set<TrustAnchor> {
        val (entity, service) = when (case) {
            VerificationCase.EU_WIA -> Entity.WalletProvider to Service.Issuance
            VerificationCase.EU_WUA -> Entity.WalletProvider to Service.Issuance
            VerificationCase.EU_WUA_STATUS -> Entity.WalletProvider to Service.Revocation
            VerificationCase.EU_PID -> Entity.PIDProvider to Service.Issuance
            VerificationCase.EU_PID_STATUS -> Entity.PIDProvider to Service.Revocation
            VerificationCase.EU_QEAA -> Entity.QEAAProvider to Service.Issuance
            VerificationCase.EU_QEAA_STATUS -> Entity.QEAAProvider to Service.Revocation
            VerificationCase.EU_PUB_EAA -> Entity.PubEAAProvider to Service.Issuance
            VerificationCase.EU_PUB_EAA_STATUS -> Entity.PubEAAProvider to Service.Revocation
            VerificationCase.EU_EAA -> Entity.EAAProvider to Service.Issuance
            VerificationCase.EU_EAA_STATUS -> Entity.EAAProvider to Service.Revocation
            VerificationCase.EU_WRPRC -> Entity.WalletRelyingPartyRegistrationCertificateProvider to Service.Issuance
            VerificationCase.EU_WRPRC_STATUS -> Entity.WalletRelyingPartyRegistrationCertificateProvider to Service.Revocation
            VerificationCase.EU_WRPAC -> Entity.WalletRelyingPartyAccessCertificateProvider to Service.Issuance
            VerificationCase.EU_WRPAC_STATUS -> Entity.WalletRelyingPartyAccessCertificateProvider to Service.Revocation
        }
        return getTrustAnchors(entity, service)
    }

    override fun afterPropertiesSet() {
        runBlocking {
            refresh()
        }
    }
}

operator fun TrustSourceManager.plus(other: TrustSourceManager): TrustSourceManager =
    object : TrustSourceManager {
        override suspend fun getTrustAnchors(
            entity: Entity,
            service: Service,
        ): Set<TrustAnchor> = this@plus.getTrustAnchors(entity, service) + other.getTrustAnchors(entity, service)

        override suspend fun refresh() {
            this@plus.refresh()
            other.refresh()
        }
    }
