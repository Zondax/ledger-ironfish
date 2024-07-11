/** ******************************************************************************
 *  (c) 2018 - 2024 Zondax AG
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

import Zemu from '@zondax/zemu'
import { defaultOptions, models } from './common'
import IronfishApp from '@zondax/ledger-ironfish'

jest.setTimeout(45000)

describe('DKG', function () {
  test.concurrent.each(models)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
    } finally {
      await sim.close()
    }
  })


  test.concurrent.each(models)('get Identity', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new IronfishApp(sim.getTransport())
      const respIdentity = await app.dkgGetIdentity()

      console.log(respIdentity)
      console.log(respIdentity.verificationKey?.toString('hex'))
      console.log(respIdentity.encryptionKey?.toString('hex'))
      console.log(respIdentity.signature?.toString('hex'))

      expect(respIdentity.returnCode).toEqual(0x9000)
      expect(respIdentity.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

})
