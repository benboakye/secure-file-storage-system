import type { ApiUpload, UploadStatus } from './apiClient'

export const MAX_UPLOAD_BYTES = 25 * 1024 * 1024

export type UploadCandidate = {
  id: string
  correlationId: string
  name: string
  size: number
  mediaType: string
  detectedMediaType?: string
  status: UploadStatus | 'selected'
  progress: number
  decisionReason?: string
  file?: File
}

export type InspectionDecision = 'accepted' | 'rejected' | 'failed'

export const DEMO_UPLOAD: UploadCandidate = {
  id: 'upl_7G2K9P',
  correlationId: 'corr_7G2K9P',
  name: 'security-training.pdf',
  size: 2.4 * 1024 * 1024,
  mediaType: 'application/pdf',
  detectedMediaType: 'application/pdf',
  status: 'selected',
  progress: 0,
}

export function createUploadCandidate(file: File): UploadCandidate {
  return {
    id: `local_${crypto.randomUUID()}`,
    correlationId: '',
    name: file.name,
    size: file.size,
    mediaType: file.type || 'application/octet-stream',
    status: 'selected',
    progress: 0,
    file,
  }
}

export function uploadCandidateFromAPI(upload: ApiUpload): UploadCandidate {
  return {
    id: upload.id,
    correlationId: upload.correlationId,
    name: upload.name,
    size: upload.size,
    mediaType: upload.declaredMediaType,
    detectedMediaType: upload.detectedMediaType,
    status: upload.status,
    progress: upload.progress,
    decisionReason: upload.decisionReason,
  }
}

export function validateUpload(file: File): string | null {
  if (!file.name.trim()) return 'Choose a file with a valid name.'
  if (file.size === 0) return 'Empty files cannot be uploaded.'
  if (file.size > MAX_UPLOAD_BYTES) return 'This file exceeds the 25 MiB development limit.'
  return null
}

export function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(bytes < 10 * 1024 * 1024 ? 1 : 0)} MB`
}
