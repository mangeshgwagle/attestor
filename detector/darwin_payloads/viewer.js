'use strict';

(() => {
  const MAX_SEARCH_RESULTS = 100;
  const MAX_INTRUDER_PREVIEW = 50;
  const byId = id => document.getElementById(id);
  const elements = {
    categories: byId('categoryList'), search: byId('searchBox'), empty: byId('emptyState'),
    tabs: byId('tabs'), title: byId('viewTitle'), stats: byId('stats'),
    payloads: byId('payloadsView'), readme: byId('readmeView'), intruders: byId('intrudersView')
  };
  let allData = {categories: []};
  let currentCategory = '';
  let searchTimer = 0;

  function safeString(value) { return typeof value === 'string' ? value : String(value ?? ''); }
  function categoryPayloads(category) { return Array.isArray(category.payloads) ? category.payloads : []; }
  function categoryIntruders(category) {
    return category.intruders && typeof category.intruders === 'object' && !Array.isArray(category.intruders)
      ? category.intruders : {};
  }

  function showMessage(view, message) {
    const item = document.createElement('div');
    item.className = 'empty-state';
    item.textContent = message;
    view.replaceChildren(item);
  }

  async function copyToClipboard(button, text) {
    try {
      await navigator.clipboard.writeText(text);
      button.textContent = 'Copied';
      button.classList.add('copied');
      window.setTimeout(() => {
        button.textContent = button.dataset.defaultLabel || 'Copy';
        button.classList.remove('copied');
      }, 1500);
    } catch (_error) {
      button.textContent = 'Copy failed';
      button.classList.add('copy-failed');
      window.setTimeout(() => {
        button.textContent = button.dataset.defaultLabel || 'Copy';
        button.classList.remove('copy-failed');
      }, 1800);
    }
  }

  function createCard(category, type, preview, copyText, copyLabel = 'Copy') {
    const card = document.createElement('article');
    card.className = 'payload-card';
    const header = document.createElement('header');
    header.className = 'payload-header';
    const categoryLabel = document.createElement('span');
    categoryLabel.className = 'payload-category';
    categoryLabel.textContent = category;
    const typeLabel = document.createElement('span');
    typeLabel.className = 'payload-type';
    typeLabel.textContent = type;
    header.append(categoryLabel, typeLabel);
    const code = document.createElement('pre');
    code.className = 'payload-code';
    code.textContent = preview;
    const copy = document.createElement('button');
    copy.className = 'copy-btn';
    copy.type = 'button';
    copy.dataset.defaultLabel = copyLabel;
    copy.textContent = copyLabel;
    copy.addEventListener('click', () => copyToClipboard(copy, copyText));
    card.append(header, code, copy);
    return card;
  }

  function renderCategories() {
    const fragment = document.createDocumentFragment();
    const categories = allData.categories.slice().sort((left, right) =>
      safeString(left.category).localeCompare(safeString(right.category)));
    categories.forEach(category => {
      const name = safeString(category.category);
      const payloadCount = categoryPayloads(category).length;
      const intruderCount = Object.values(categoryIntruders(category)).reduce(
        (total, values) => total + (Array.isArray(values) ? values.length : 0), 0);
      const item = document.createElement('li');
      const button = document.createElement('button');
      button.className = 'category-item';
      button.type = 'button';
      button.dataset.category = name;
      button.setAttribute('aria-pressed', 'false');
      const label = document.createElement('span');
      label.textContent = name;
      const count = document.createElement('span');
      count.className = 'count';
      count.textContent = String(payloadCount + intruderCount);
      button.append(label, count);
      button.addEventListener('click', () => selectCategory(name));
      item.append(button);
      fragment.append(item);
    });
    elements.categories.replaceChildren(fragment);
  }

  function setTab(name) {
    document.querySelectorAll('[role="tab"]').forEach(tab => {
      const selected = tab.dataset.tab === name;
      tab.classList.toggle('active', selected);
      tab.setAttribute('aria-selected', String(selected));
      tab.tabIndex = selected ? 0 : -1;
    });
    elements.payloads.classList.toggle('hidden', name !== 'payloads');
    elements.readme.classList.toggle('hidden', name !== 'readme');
    elements.intruders.classList.toggle('hidden', name !== 'intruders');
  }

  function selectCategory(categoryName) {
    currentCategory = categoryName;
    document.querySelectorAll('.category-item').forEach(item => {
      const selected = item.dataset.category === categoryName;
      item.classList.toggle('active', selected);
      item.setAttribute('aria-pressed', String(selected));
    });
    const category = allData.categories.find(item => safeString(item.category) === categoryName);
    if (!category) return;
    elements.empty.classList.add('hidden');
    elements.tabs.classList.remove('hidden');
    elements.title.textContent = categoryName;
    const payloadCount = categoryPayloads(category).length;
    const intruderCount = Object.values(categoryIntruders(category)).reduce(
      (total, values) => total + (Array.isArray(values) ? values.length : 0), 0);
    const fileCount = Array.isArray(category.files) ? category.files.length : 0;
    elements.stats.textContent = `${payloadCount} README payloads · ${intruderCount} intruder payloads · ${fileCount} files`;
    renderPayloads(category);
    renderReadme(category);
    renderIntruders(category);
    setTab('payloads');
  }

  function renderPayloads(category) {
    const payloads = categoryPayloads(category).filter(value => typeof value === 'string');
    if (!payloads.length) {
      showMessage(elements.payloads, 'No README payloads in this category.');
      return;
    }
    const fragment = document.createDocumentFragment();
    payloads.forEach(payload => fragment.append(createCard(
      safeString(category.category), 'README', payload, payload)));
    elements.payloads.replaceChildren(fragment);
  }

  function renderReadme(category) {
    const source = category.readme && typeof category.readme.full_content === 'string'
      ? category.readme.full_content : '';
    if (!source) {
      showMessage(elements.readme, 'No README source is available for this category.');
      return;
    }
    const pre = document.createElement('pre');
    pre.className = 'readme-source';
    pre.textContent = source;
    elements.readme.replaceChildren(pre);
  }

  function renderIntruders(category) {
    const entries = Object.entries(categoryIntruders(category));
    if (!entries.length) {
      showMessage(elements.intruders, 'No intruder files in this category.');
      return;
    }
    const fragment = document.createDocumentFragment();
    entries.forEach(([filename, rawPayloads]) => {
      const payloads = Array.isArray(rawPayloads)
        ? rawPayloads.filter(value => typeof value === 'string') : [];
      const preview = payloads.slice(0, MAX_INTRUDER_PREVIEW).join('\n') +
        (payloads.length > MAX_INTRUDER_PREVIEW
          ? `\n… and ${payloads.length - MAX_INTRUDER_PREVIEW} more` : '');
      fragment.append(createCard(
        safeString(category.category), `Intruder: ${safeString(filename)} (${payloads.length})`,
        preview, payloads.join('\n'), 'Copy all'));
    });
    elements.intruders.replaceChildren(fragment);
  }

  function performSearch(rawQuery) {
    const query = safeString(rawQuery).trim().slice(0, 200);
    if (!query) {
      if (currentCategory) selectCategory(currentCategory);
      return;
    }
    const needle = query.toLocaleLowerCase();
    const results = [];
    let matchCount = 0;
    allData.categories.forEach(category => {
      categoryPayloads(category).forEach(payload => {
        if (typeof payload === 'string' && payload.toLocaleLowerCase().includes(needle)) {
          matchCount += 1;
          if (results.length < MAX_SEARCH_RESULTS) {
            results.push({category: safeString(category.category), type: 'README', payload});
          }
        }
      });
      Object.entries(categoryIntruders(category)).forEach(([filename, payloads]) => {
        if (!Array.isArray(payloads)) return;
        payloads.forEach(payload => {
          if (typeof payload === 'string' && payload.toLocaleLowerCase().includes(needle)) {
            matchCount += 1;
            if (results.length < MAX_SEARCH_RESULTS) {
              results.push({category: safeString(category.category), type: `Intruder: ${safeString(filename)}`, payload});
            }
          }
        });
      });
    });
    elements.empty.classList.add('hidden');
    elements.tabs.classList.add('hidden');
    elements.title.textContent = `Search: “${query}”`;
    elements.stats.textContent = matchCount > results.length
      ? `${matchCount} matches · first ${results.length} shown` : `${matchCount} matches`;
    elements.readme.classList.add('hidden');
    elements.intruders.classList.add('hidden');
    elements.payloads.classList.remove('hidden');
    if (!results.length) {
      showMessage(elements.payloads, 'No results found.');
      return;
    }
    const fragment = document.createDocumentFragment();
    results.forEach(result => fragment.append(createCard(
      result.category, result.type, result.payload, result.payload)));
    elements.payloads.replaceChildren(fragment);
  }

  async function loadData() {
    try {
      const response = await fetch('payloads.json', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const parsed = await response.json();
      if (!parsed || !Array.isArray(parsed.categories)) throw new Error('Invalid payload catalog shape');
      allData = {categories: parsed.categories.filter(item => item && typeof item === 'object')};
      renderCategories();
      elements.stats.textContent = `${allData.categories.length} categories loaded locally`;
    } catch (error) {
      elements.title.textContent = 'Unable to load payload data';
      elements.stats.textContent = '';
      showMessage(elements.empty, `The local payload catalog could not be loaded: ${safeString(error.message)}`);
    }
  }

  elements.search.addEventListener('input', event => {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => performSearch(event.target.value), 200);
  });
  document.querySelectorAll('[role="tab"]').forEach(tab => {
    tab.addEventListener('click', () => setTab(tab.dataset.tab));
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
      const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
      const offset = event.key === 'ArrowRight' ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + offset + tabs.length) % tabs.length];
      setTab(next.dataset.tab);
      next.focus();
      event.preventDefault();
    });
  });

  loadData();
})();
