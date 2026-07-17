async function jsonRequest(url, options) {
  const response = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function byId(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  byId(id).textContent = text;
}

function splitLines(value) {
  return String(value || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function renderDomain(domain) {
  const root = byId("domainDetails");
  if (!domain) {
    root.innerHTML = "<p>Select a domain to inspect its guardrails and signals.</p>";
    return;
  }
  root.innerHTML = `
    <section>
      <h3>${domain.title}</h3>
      <p>${domain.purpose || ""}</p>
    </section>
    <section>
      <h3>Signals</h3>
      <ul>${(domain.signals || []).map((item) => `<li>${item}</li>`).join("")}</ul>
    </section>
    <section>
      <h3>Recipe queries</h3>
      <ul>${(domain.recipe_queries || []).map((item) => `<li>${item}</li>`).join("")}</ul>
    </section>
    <section>
      <h3>Domain page</h3>
      <p>${domain.page || "No linked page."}</p>
    </section>
  `;
}

function renderSuiteMeta(suite, domainCount) {
  const list = byId("suiteMeta");
  list.innerHTML = `
    <dt>Name</dt><dd>${suite.name || "security-recipes.ai remediation suite"}</dd>
    <dt>Version</dt><dd>${suite.version || "unknown"}</dd>
    <dt>Entrypoint</dt><dd>${suite.python_entrypoint || "scripts/security_recipes_remediation_suite.py"}</dd>
    <dt>Domains</dt><dd>${domainCount}</dd>
    <dt>LLM modes</dt><dd>${(suite.llm_modes || []).join(", ")}</dd>
  `;
}

function configFromForm() {
  return {
    domain: byId("domainSelect").value,
    recipes_source: byId("recipesSource").value.trim(),
    tooling: byId("tooling").value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    ecosystem: byId("ecosystem").value.trim(),
    llm_mode: byId("llmMode").value,
    max_recipes: Number(byId("maxRecipes").value || 6),
    finding_input: byId("findingInput").value,
    llm_config: {
      endpoint: byId("llmEndpoint").value.trim(),
      model: byId("llmModel").value.trim(),
      api_key_env: byId("llmApiKeyEnv").value.trim(),
      temperature: Number(byId("llmTemperature").value || 0.2),
      timeout: Number(byId("llmTimeout").value || 30),
    },
    access_context: {
      notes: byId("accessNotes").value.trim(),
      context_sources: splitLines(byId("contextSources").value),
    },
  };
}

function applyConfig(config, options = {}) {
  byId("domainSelect").value = config.domain || "recommend";
  byId("recipesSource").value = config.recipes_source || "";
  byId("tooling").value = (config.tooling || []).join(", ");
  byId("ecosystem").value = config.ecosystem || "";
  byId("llmMode").value = config.llm_mode || "prompt";
  byId("maxRecipes").value = config.max_recipes || 6;
  if (!options.preserveFindingInput) {
    byId("findingInput").value = config.finding_input || "";
  }
  byId("llmEndpoint").value = config.llm_config?.endpoint || "";
  byId("llmModel").value = config.llm_config?.model || "";
  byId("llmApiKeyEnv").value = config.llm_config?.api_key_env || "";
  byId("llmTemperature").value = config.llm_config?.temperature ?? 0.2;
  byId("llmTimeout").value = config.llm_config?.timeout ?? 30;
  byId("accessNotes").value = config.access_context?.notes || "";
  byId("contextSources").value = (config.access_context?.context_sources || []).join("\n");
}

function downloadJson(name, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

let suiteState = { domains: [], latestPacket: null };

async function init() {
  try {
    const [{ suite, domains }, config] = await Promise.all([
      jsonRequest("/api/domains"),
      jsonRequest("/api/config"),
    ]);
    suiteState.domains = domains;
    const select = byId("domainSelect");
    domains.forEach((domain) => {
      const option = document.createElement("option");
      option.value = domain.id;
      option.textContent = `${domain.command} - ${domain.title}`;
      select.appendChild(option);
    });
    renderSuiteMeta(suite || {}, domains.length);
    applyConfig(config);
    renderDomain(domains.find((item) => item.id === (config.domain || "recommend")) || domains[0]);
    setText("health", "Ready");
  } catch (error) {
    setText("health", `Load failed: ${error.message}`);
  }
}

byId("domainSelect").addEventListener("change", () => {
  renderDomain(suiteState.domains.find((item) => item.id === byId("domainSelect").value));
});

byId("loadDomainDefaults").addEventListener("click", () => {
  renderDomain(suiteState.domains.find((item) => item.id === byId("domainSelect").value));
});

byId("saveConfig").addEventListener("click", async () => {
  try {
    const result = await jsonRequest("/api/config", {
      method: "POST",
      body: JSON.stringify(configFromForm()),
    });
    applyConfig(result.config, { preserveFindingInput: true });
    setText("health", "Configuration saved");
  } catch (error) {
    setText("health", `Save failed: ${error.message}`);
  }
});

byId("planForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  setText("health", "Generating packet");
  try {
    const result = await jsonRequest("/api/plan", {
      method: "POST",
      body: JSON.stringify(configFromForm()),
    });
    suiteState.latestPacket = result.packet;
    byId("packetPreview").textContent = JSON.stringify(result.packet, null, 2);
    byId("promptPreview").textContent =
      result.packet?.agent_handoff?.prompt || "No prompt returned for this domain.";
    byId("downloadPacket").disabled = false;
    setText("health", "Packet generated");
  } catch (error) {
    byId("packetPreview").textContent = error.message;
    setText("health", `Generation failed: ${error.message}`);
  }
});

byId("downloadPacket").addEventListener("click", () => {
  if (!suiteState.latestPacket) return;
  const domain = suiteState.latestPacket.domain?.command || "packet";
  downloadJson(`security-recipes-${domain}-packet.json`, suiteState.latestPacket);
});

init();
