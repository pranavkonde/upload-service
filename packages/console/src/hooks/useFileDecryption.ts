import { useW3 } from '@storacha/ui-react'
import { useState } from 'react'
import type { Space, UnknownLink } from '@storacha/ui-react'
import { parse as parseLink } from 'multiformats/link'
import { create as createEncryptedClient } from '@storacha/encrypt-upload-client'
import { useKMSConfig } from '@storacha/ui-react'

interface DecryptionState {
  loading: boolean
  error: string | null
}

export const useFileDecryption = (space?: Space) => {
  const [{ client }] = useW3()
  const [state, setState] = useState<DecryptionState>({
    loading: false,
    error: null
  })

  const { createKMSAdapter, isConfigured } = useKMSConfig()

  const downloadBlob = (blob: Blob, filename: string) => {
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const streamToBlob = async (stream: ReadableStream): Promise<Blob> => {
    const reader = stream.getReader()
    const chunks: Uint8Array[] = []
    let done = false
    
    while (!done) {
      const { value, done: isDone } = await reader.read()
      done = isDone
      if (value) {
        chunks.push(value)
      }
    }
    
    return new Blob(chunks)
  }

  const decryptAndDownload = async (cid: UnknownLink | string, filename: string) => {
    if (!client || !space || space.access?.type !== 'private') {
      throw new Error('Invalid state: client, space, or private space access required')
    }

    setState({ loading: true, error: null })

    try {
      // Create crypto adapter using shared KMS config
      const cryptoAdapter = await createKMSAdapter()
      if (!cryptoAdapter) {
        throw new Error('KMS configuration required for decryption')
      }

      // Create encrypted client
      const encryptedClient = await createEncryptedClient({
        storachaClient: client,
        cryptoAdapter
      })

      // Parse CID if it's a string
      const encryptionMetadataCID = typeof cid === 'string' ? parseLink(cid) : cid

      const proofs = client.proofs([
        {
          can: 'space/*',
          with: space.did()
        }
      ])

      // Generate a decryption delegation on the fly for the agent (agent already has space/* capability)
      const decryptDelegation = await client.createDelegation(
        client.agent.issuer, // delegate to self for decryption
        // @ts-expect-error TODO: include the space/content/decrypt to the API for type inference
        ['space/content/decrypt'], // Use space/* which includes space/content/decrypt
        {
          expiration: Math.floor(Date.now() / 1000) + 60 * 15, // 15 minutes
          proofs,
        },
      )
      
      const delegationCAR = await decryptDelegation.archive()
      if (delegationCAR.error) {
        throw new Error(`Failed to create delegation: ${delegationCAR.error.message}`)
      }

      // Downloads the encrypted file, and decrypts it locally
      const decryptedStream = await encryptedClient.retrieveAndDecryptFile(
        encryptionMetadataCID,
        {
          spaceDID: space.did(),
          decryptDelegation,  
        }
      )

      // Convert stream to blob to allow user to download the decrypted file
      const blob = await streamToBlob(decryptedStream)
      downloadBlob(blob, filename)

      setState({ loading: false, error: null })
    } catch (error) {
      console.error('Decryption failed:', error)
      setState({ 
        loading: false, 
        error: error instanceof Error ? error.message : 'Decryption failed' 
      })
      throw error
    }
  }

  const canDecrypt = Boolean(
    client && 
    space && 
    space.access?.type === 'private' &&
    isConfigured
  )

  return {
    decryptAndDownload,
    canDecrypt,
    loading: state.loading,
    error: state.error
  }
} 