import React from 'react';

// Exposure Score is a 0-100 risk index (higher = MORE exposed = worse), graded
// A–F. The backend computes it per scan (insights `exposure` block + per-domain
// `exposure_score`/`exposure_grade` on the dashboard); these components surface it.

// Grade → theme colours. A/B are green (good), C yellow, D orange, F red.
export function gradeClasses(grade) {
  switch ((grade || '').toUpperCase()) {
    case 'A': return { text: 'text-green-400',  border: 'border-green-800',  bg: 'bg-green-900/10' };
    case 'B': return { text: 'text-brand',      border: 'border-brand/30',   bg: 'bg-brand/10' };
    case 'C': return { text: 'text-yellow-400', border: 'border-yellow-800', bg: 'bg-yellow-900/10' };
    case 'D': return { text: 'text-orange-400', border: 'border-orange-800', bg: 'bg-orange-900/10' };
    case 'F': return { text: 'text-red-400',    border: 'border-red-800',    bg: 'bg-red-900/10' };
    default:  return { text: 'text-body',       border: 'border-rim',        bg: 'bg-card' };
  }
}

// Compact grade+score pill for table cells (Dashboard Domain Status).
export function ExposureBadge({ score, grade }) {
  if (score == null && !grade) return <span className="text-dim">—</span>;
  const g = gradeClasses(grade);
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-semibold ${g.border} ${g.bg} ${g.text}`}>
      <span>{grade || '?'}</span>
      {score != null && <span className="opacity-80">{score}</span>}
    </span>
  );
}

// Higher exposure = worse, so an upward move is red and a downward move green.
function ExposureTrend({ direction, change, hasBaseline }) {
  if (!hasBaseline) {
    return <div className="text-dim text-xs text-right leading-snug">No prior scan<br />to compare</div>;
  }
  const up = direction === 'up';
  const down = direction === 'down';
  const cls = up ? 'text-red-400' : down ? 'text-green-400' : 'text-dim';
  const arrow = up ? '↑' : down ? '↓' : '→';
  const label = up ? 'more exposure' : down ? 'less exposure' : 'no change';
  return (
    <div className={`text-right ${cls}`}>
      <div className="text-2xl font-bold leading-none">{arrow} {Math.abs(change ?? 0)}</div>
      <div className="text-xs mt-1">{label} vs last scan</div>
    </div>
  );
}

// Hero card for the Insights page. Returns null when no score is available so
// pages can render it unconditionally.
export function ExposureCard({ exposure }) {
  if (!exposure || exposure.score == null) return null;
  const { score, grade, direction, change, previous_score } = exposure;
  const g = gradeClasses(grade);
  return (
    <div className={`rounded-xl border p-5 flex items-center gap-5 sm:gap-6 ${g.border} ${g.bg}`}>
      <div className={`flex items-center justify-center w-16 h-16 shrink-0 rounded-xl border text-3xl font-bold ${g.border} ${g.text}`}>
        {grade || '—'}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-semibold uppercase tracking-wider text-dim">Exposure Score</div>
        <div className="flex items-baseline gap-1.5 mt-0.5">
          <span className={`text-4xl font-bold leading-none ${g.text}`}>{score}</span>
          <span className="text-dim text-sm">/ 100</span>
        </div>
        <div className="text-dim text-xs mt-1.5">Lower is better — weighted by severity, exposure &amp; exploitability</div>
      </div>
      <ExposureTrend direction={direction} change={change} hasBaseline={previous_score != null} />
    </div>
  );
}
