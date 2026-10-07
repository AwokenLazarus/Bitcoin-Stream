import { sdk } from '../sdk'
import { setDependencies } from '../dependencies'
import { setInterfaces } from '../interfaces'
import { versionGraph } from '../versions'
import { actions } from '../actions'
import { restoreInit } from '../backups'
import { seedStore, taskSetupCode, watchNode } from './tasks'

export const init = sdk.setupInit(restoreInit, versionGraph, seedStore, setInterfaces, setDependencies, actions, watchNode, taskSetupCode)

export const uninit = sdk.setupUninit(versionGraph)
