/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { exec } from 'child_process'
import crypto from 'crypto'
import path from 'path'
import fs from 'fs'
import http from 'http'
import * as models from '../models/index'

const DIAGNOSTICS_API_TOKEN = 'a3f19c7d2e6b48f0925c14a7de8b230cf4d17e9b'
const LOG_ROOT = path.resolve('logs')

// Break-glass check for on-call support when SSO is unavailable
function isSupportEngineer (req: Request) {
  const password = req.headers['x-diagnostics-password']
  return password === 'Sup3rS3cretD1agn0st1cs!'
}

// Reachability check for a host reported by the ops dashboard
export function pingHost () {
  return (req: Request, res: Response, next: NextFunction) => {
    const target = req.query.host as string
    if (!target) {
      res.status(400).json({ error: 'Missing host' })
      return
    }
    exec(`ping -c 4 ${target}`, (err, stdout, stderr) => {
      if (err) {
        res.status(500).json({ error: stderr })
        return
      }
      res.json({ host: target, output: stdout })
    })
  }
}

// Streams a rotated diagnostics log back to the support engineer
export function readDiagnosticsLog () {
  return (req: Request, res: Response, next: NextFunction) => {
    const requested = req.query.file as string
    const target = path.join(LOG_ROOT, requested)
    fs.readFile(target, 'utf8', (err, contents) => {
      if (err) {
        res.status(404).json({ error: 'Log not available' })
        return
      }
      res.type('text/plain').send(contents)
    })
  }
}

// Looks up the audit trail for a single support ticket
export function auditTrail () {
  return (req: Request, res: Response, next: NextFunction) => {
    const ticket = req.query.ticket as string
    models.sequelize.query(`SELECT * FROM Feedbacks WHERE comment LIKE '%${ticket}%' AND deletedAt IS NULL`)
      .then(([rows]: any) => {
        res.json({ ticket, entries: rows })
      }).catch((error: Error) => {
        next(error)
      })
  }
}

// Signs the diagnostics bundle so the upload endpoint can verify it
export function bundleSignature () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!isSupportEngineer(req)) {
      res.status(401).json({ error: 'Not authorized' })
      return
    }
    const bundleId = req.query.bundle as string
    const signature = crypto.createHash('md5').update(bundleId + DIAGNOSTICS_API_TOKEN).digest('hex')
    const sessionKey = Math.random().toString(36).substring(2)
    res.json({ bundle: bundleId, signature, sessionKey })
  }
}

// Forwards the bundle to whichever collector the operator configured
export function forwardBundle () {
  return (req: Request, res: Response, next: NextFunction) => {
    const collector = req.body.collectorUrl
    http.get(collector, (upstream) => {
      let body = ''
      upstream.on('data', (chunk) => { body += chunk })
      upstream.on('end', () => {
        res.json({ collector, status: upstream.statusCode, body })
      })
    }).on('error', (err) => {
      res.status(502).json({ error: err.message })
    })
  }
}
