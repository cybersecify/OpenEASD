import { describe, it, expect } from 'vitest';
import ScanStartPage, { buildScanModes } from './ScanStartPage.jsx';

const WF = [
  { id: 1, name: 'Full Scan',    is_default: true,  is_passive: false, steps: [{enabled:true},{enabled:true}] },
  { id: 2, name: 'Passive Scan', is_default: false, is_passive: true,  steps: [{enabled:true}] },
  { id: 3, name: 'Passive Scan Light',  is_default: false, is_passive: true,  steps: [{enabled:true}] },
  { id: 4, name: 'Active Light', is_default: false, is_passive: false, steps: [{enabled:true}] },
];

describe('buildScanModes', () => {
  it('returns the four cells in matrix order: passive-light, passive-deep, active-light, active-deep', () => {
    const modes = buildScanModes(WF);
    expect(modes.map(m => m.key)).toEqual(['quick', 'passive', 'active_light', 'full']);
  });

  it('binds each cell to its workflow by name', () => {
    const byKey = Object.fromEntries(buildScanModes(WF).map(m => [m.key, m]));
    expect(byKey.quick.workflow.name).toBe('Passive Scan Light');
    expect(byKey.passive.workflow.name).toBe('Passive Scan');
    expect(byKey.active_light.workflow.name).toBe('Active Light');
    expect(byKey.full.workflow.name).toBe('Full Scan');
  });

  it('marks passive cells no-auth and active cells auth-required', () => {
    const byKey = Object.fromEntries(buildScanModes(WF).map(m => [m.key, m]));
    expect(byKey.quick.needsAuth).toBe(false);
    expect(byKey.passive.needsAuth).toBe(false);
    expect(byKey.active_light.needsAuth).toBe(true);
    expect(byKey.full.needsAuth).toBe(true);
  });

  it('omits a cell whose workflow is absent (older DB)', () => {
    const noLight = WF.filter(w => w.name !== 'Active Light' && w.name !== 'Passive Scan Light');
    const keys = buildScanModes(noLight).map(m => m.key);
    expect(keys).toEqual(['passive', 'full']);
  });
});

describe('ScanStartPage module', () => {
  it('exports a default component', () => {
    expect(typeof ScanStartPage).toBe('function');
  });
});
