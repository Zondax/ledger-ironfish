/** ******************************************************************************
 *  (c) 2018 - 2023 Zondax AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */

import Zemu, { ButtonKind, zondaxMainmenuNavigation } from '@zondax/zemu'
import { defaultOptions, models, txBlobExample } from './common'
import IronfishApp from '@zondax/ledger-ironfish'

jest.setTimeout(60000)

const PATH = "m/44'/133'/0'/0/0"

const expectedPublicAddress = "b3ad098e86bc31de35ec5a77cce6aed08d5336bf273abef5e7eb420278a0c19c"
const expectedIVK = "043e34aa9a6323b82a899d984081ce53e3bb47b2ffa18a0dcfa6910a6d278c73"
const expectedOVK = "316c96f058f7e188acc90d90d1d765bd9b9ce9e5fa3655c74e8450df0191ee21"

describe('Standard', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const nav = zondaxMainmenuNavigation(m.name, [1, 0, 0, 4, -5])
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, nav.schedule)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport())

      const resp = await app.getAddressAndPubKey(PATH)
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      expect(resp.publicAddress?.toString('hex')).toEqual(expectedPublicAddress)
      expect(resp.ivk?.toString('hex')).toEqual(expectedIVK)
      expect(resp.ovk?.toString('hex')).toEqual(expectedOVK)
    } finally {
      await sim.close()
    }
  })

  test.concurrent.each(models)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({...defaultOptions, model: m.name,
                       approveKeyword: m.name === 'stax' ? 'QR' : '',
                       approveAction: ButtonKind.ApproveTapButton,})
      const app = new IronfishApp(sim.getTransport())

      const respRequest = app.showAddressAndPubKey(PATH)
      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest
      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  // test.concurrent.each(models)('show address - reject', async function (m) {
  //   const sim = new Zemu(m.path)
  //   try {
  //     await sim.start({...defaultOptions, model: m.name,
  //                      rejectKeyword: m.name === 'stax' ? 'QR' : ''})
  //     const app = new TemplateApp(sim.getTransport())

  //     const respRequest = app.getAddressAndPubKey(accountId, true)
  //     // Wait until we are not in the main menu
  //     await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

  //     await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_reject`, 'REJECT')

  //     const resp = await respRequest
  //     console.log(resp)

  //     expect(resp.return_code).toEqual(0x6986)
  //     expect(resp.error_message).toEqual('Transaction rejected')
  //   } finally {
  //     await sim.close()
  //   }
  // })

  // #{TODO} --> Add Zemu tests for different transactions. Include expert mode if needed
  // test.concurrent.each(models)('sign tx0 normal', async function (m) {
  //   const sim = new Zemu(m.path)
  //   try {
  //     await sim.start({ ...defaultOptions, model: m.name })
  //     const app = new TemplateApp(sim.getTransport())

  //     const txBlob = Buffer.from(txBlobExample)
  //     const responseAddr = await app.getAddressAndPubKey(accountId)
  //     const pubKey = responseAddr.publicKey

  //     // do not wait here.. we need to navigate
  //     const signatureRequest = app.sign(accountId, txBlob)

  //     // Wait until we are not in the main menu
  //     await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //     await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_asset_freeze`,50000)

  //     const signatureResponse = await signatureRequest
  //     console.log(signatureResponse)

  //     expect(signatureResponse.return_code).toEqual(0x9000)
  //     expect(signatureResponse.error_message).toEqual('No errors')

  //     // Now verify the signature
  //     const prehash = Buffer.concat([Buffer.from('TX'), txBlob]);
  //     const valid = ed25519.verify(signatureResponse.signature, prehash, pubKey)
  //     expect(valid).toEqual(true)
  //   } finally {
  //     await sim.close()
  //   }
  // })

  // test.concurrent.each(models)('sign tx1 normal', async function (m) {
  //   const sim = new Zemu(m.path)
  //   try {
  //     await sim.start({ ...defaultOptions, model: m.name })
  //     const app = new TemplateApp(sim.getTransport())

  //     const txBlob = Buffer.from(txBlobExample)
  //     const responseAddr = await app.getAddressAndPubKey(accountId)
  //     const pubKey = responseAddr.publicKey

  //     // do not wait here.. we need to navigate
  //     const signatureRequest = app.sign(accountId, txBlob)

  //     // Wait until we are not in the main menu
  //     await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())
  //     await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_asset_freeze`,50000)

  //     const signatureResponse = await signatureRequest
  //     console.log(signatureResponse)

  //     expect(signatureResponse.return_code).toEqual(0x9000)
  //     expect(signatureResponse.error_message).toEqual('No errors')

  //     // Now verify the signature
  //     const prehash = Buffer.concat([Buffer.from('TX'), txBlob]);
  //     const valid = ed25519.verify(signatureResponse.signature, prehash, pubKey)
  //     expect(valid).toEqual(true)
  //   } finally {
  //     await sim.close()
  //   }
  // })
})
