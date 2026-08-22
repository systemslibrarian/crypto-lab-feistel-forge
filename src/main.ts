/**
 * Entry point: tab wiring and lazy panel rendering.
 *
 * Panels render on first activation and not before, so a tab that has never
 * been clicked is a panel that is empty in the DOM. That is deliberate — an
 * empty region is exactly what an accessibility scan reports as perfectly
 * accessible, so the a11y gate asserts emptiness on arrival and non-emptiness
 * after each activation, which turns "a renderer threw" into a failure rather
 * than a clean scan.
 *
 * There is no theme logic here. Dark is the only theme, pinned in the document
 * head before first paint.
 */
import './style.css';
import { renderRoundPanel } from './ui/roundPanel';
import { renderCircuitPanel } from './ui/circuitPanel';
import { renderComplementPanel } from './ui/complementPanel';
import { renderMitmPanel } from './ui/mitmPanel';
import { renderSweet32Panel } from './ui/sweet32Panel';
import { renderVectorsPanel } from './ui/vectorsPanel';

type Renderer = (root: HTMLElement) => void;

const RENDERERS: Record<string, Renderer> = {
  round: renderRoundPanel,
  circuit: renderCircuitPanel,
  complement: renderComplementPanel,
  mitm: renderMitmPanel,
  sweet32: renderSweet32Panel,
  vectors: renderVectorsPanel,
};

const rendered = new Set<string>();

function panelFor(name: string): HTMLElement {
  const panel = document.getElementById(`panel-${name}`);
  if (!panel) throw new Error(`missing panel: panel-${name}`);
  return panel;
}

function render(name: string): void {
  if (rendered.has(name)) return;
  const renderer = RENDERERS[name];
  if (!renderer) throw new Error(`no renderer for panel: ${name}`);
  renderer(panelFor(name));
  rendered.add(name);
}

function activate(name: string, focusTab: boolean): void {
  for (const tab of document.querySelectorAll<HTMLButtonElement>('.tab-btn')) {
    const isTarget = tab.dataset.panel === name;
    tab.setAttribute('aria-selected', String(isTarget));
    tab.tabIndex = isTarget ? 0 : -1;
    const panel = panelFor(tab.dataset.panel as string);
    panel.hidden = !isTarget;
    if (isTarget && focusTab) tab.focus();
  }
  render(name);
}

function start(): void {
  const tabs = [...document.querySelectorAll<HTMLButtonElement>('.tab-btn')];
  tabs.forEach((tab, index) => {
    const name = tab.dataset.panel as string;
    tab.addEventListener('click', () => activate(name, false));
    // Arrow-key navigation is what a tablist owes a keyboard user; without it
    // the roving tabindex traps them on whichever tab is selected.
    tab.addEventListener('keydown', (event) => {
      const keys: Record<string, number> = {
        ArrowRight: index + 1,
        ArrowLeft: index - 1,
        Home: 0,
        End: tabs.length - 1,
      };
      const target = keys[event.key];
      if (target === undefined) return;
      event.preventDefault();
      const wrapped = (target + tabs.length) % tabs.length;
      activate(tabs[wrapped].dataset.panel as string, true);
    });
  });
  render('round');
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
else start();
