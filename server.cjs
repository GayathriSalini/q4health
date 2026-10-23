'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8080);
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const LLM_BASE_URL = (process.env.LLM_BASE_URL ||
  'https://aipipe.org/openai/v1').replace(/\/+$/, '');
const LLM_API_KEY = process.env.LLM_API_KEY || '';
const LLM_MODEL = process.env.LLM_MODEL || 'gpt-4.1-mini';

fs.mkdirSync(DATA_DIR, { recursive: true });

const now = () => Date.now();
const iso = n => new Date(n).toISOString();
const json = value => JSON.stringify(value);
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const clone = value => JSON.parse(JSON.stringify(value));
const id = bytes => crypto.randomBytes(bytes).toString('hex');

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function send(res, status, value) {
  const body = json(value);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store'
  });
  res.end(body);
}

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > limit) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new HttpError(400, 'Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map(k => [k, stable(value[k])])
    );
  }
  return value;
}

function canonical(value) {
  return json(stable(value));
}

function validRunId(value) {
  return typeof value === 'string' &&
    value.length > 0 && value.length <= 200 &&
    /^[A-Za-z0-9._:-]+$/.test(value);
}

function validateIncident(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, 'Expected a JSON object');
  }

  const runId = input.runId;
  if (!validRunId(runId)) {
    throw new HttpError(422, 'Invalid runId');
  }

  if (!Array.isArray(input.transcript) || input.transcript.length < 1) {
    throw new HttpError(422, 'transcript must be a non-empty array');
  }

  for (const item of input.transcript) {
    if (!item || typeof item !== 'object' ||
        typeof item.id !== 'string' ||
        typeof item.text !== 'string') {
      throw new HttpError(422, 'Invalid transcript entry');
    }
  }

  if (!Array.isArray(input.allowedRootCauses) ||
      input.allowedRootCauses.length < 1 ||
      input.allowedRootCauses.some(x => typeof x !== 'string')) {
    throw new HttpError(422, 'allowedRootCauses must be a non-empty array');
  }

  if (!input.incident || typeof input.incident !== 'object') {
    throw new HttpError(422, 'incident is required');
  }

  return runId;
}

function fileFor(runId) {
  return path.join(DATA_DIR, sha(runId) + '.json');
}

function load(runId) {
  const file = fileFor(runId);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function save(state) {
  const file = fileFor(state.runId);
  const temp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(temp, json(state), { mode: 0o600 });
  fs.renameSync(temp, file);
}

function newSpan(state, name, kind, parentId, start = now()) {
  return {
    traceId: state.traceId,
    spanId: id(8),
    parentSpanId: parentId || undefined,
    name,
    kind,
    startTimeUnixNano: String(start * 1e6),
    endTimeUnixNano: String(now() * 1e6),
    attributes: [
      { key: 'ga5.run.id', value: { stringValue: state.runId } },
      { key: 'ga5.public.marker', value: { stringValue: 'ga5' } }
    ],
    status: { code: 1 }
  };
}

function attr(span, key, value) {
  span.attributes.push({
    key,
    value: typeof value === 'number'
      ? { intValue: String(value) }
      : { stringValue: String(value) }
  });
}

function finishSpan(span, status) {
  span.endTimeUnixNano = String(now() * 1e6);
  if (status) span.status = status;
}

function addSpan(state, span) {
  state.spans.push(span);
}

function makeAction(state, toolName, args, phase) {
  const action = {
    id: id(12),
    toolName,
    args,
    phase,
    status: 'pending',
    attempts: 0,
    receipts: []
  };
  state.actionLog.push(action);
  return action;
}

function dispatch(state, action, resends = false) {
  action.attempts += 1;
  action.status = 'pending';

  const logical = newSpan(
    state, 'execute_tool ' + action.toolName, 1, state.agentSpanId
  );
  attr(logical, 'ga5.action.id', action.id);
  attr(logical, 'gen_ai.tool.name', action.toolName);
  attr(logical, 'gen_ai.tool.call.id', action.id);
  attr(logical, 'gen_ai.operation.name', 'execute_tool');
  addSpan(state, logical);
  action.logicalSpanId = logical.spanId;

  const client = newSpan(
    state, 'POST tool/' + action.toolName, 3, logical.spanId
  );
  attr(client, 'ga5.action.id', action.id);
  attr(client, 'ga5.attempt', action.attempts);
  attr(client, 'http.request.method', 'POST');
  attr(client, 'resend_count', action.attempts - 1);
  addSpan(state, client);

  action.dispatches = action.dispatches || [];
  action.dispatches.push({
    actionId: action.id,
    toolName: action.toolName,
    args: clone(action.args),
    attempt: action.attempts,
    traceparent: `00-${state.traceId}-${client.spanId}-01`
  });

  finishSpan(client);
  finishSpan(logical);
  return action.dispatches[action.dispatches.length - 1];
}

function rootServerSpan(state, parentSpanId) {
  const span = newSpan(state, 'POST /v2/incidents', 2, parentSpanId);
  return span;
}

function createTraceContext(input) {
  const header = input.traceparent;
  if (typeof header === 'string') {
    const match = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/i.exec(header);
    if (match && !/^0+$/.test(match[1]) && !/^0+$/.test(match[2])) {
      return { traceId: match[1].toLowerCase(), parentSpanId: match[2].toLowerCase() };
    }
  }
  return { traceId: id(16), parentSpanId: undefined };
}

async function callModel(input) {
  if (!LLM_API_KEY) throw new HttpError(502, 'Model API key is not configured');

  // The sensitive object is deliberately never passed to the model.
  const safeInput = {
    runId: input.runId,
    incident: input.incident,
    transcript: input.transcript,
    allowedRootCauses: input.allowedRootCauses,
    availableTools: input.availableTools || input.tools || []
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);

  try {
    const response = await fetch(LLM_BASE_URL + '/chat/completions', {
      method: 'POST',
      headers: {
        authorization: 'Bearer ' + LLM_API_KEY,
        'content-type': 'application/json'
      },
      body: json({
        model: LLM_MODEL,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: [
              'You are an incident-response planner.',
              'Return only JSON.',
              'Choose a rootCause exactly from allowedRootCauses.',
              'Include 2 to 4 distinct transcript IDs as evidence.',
              'Choose 1 to 3 minimal diagnostic actions.',
              'Never include secrets or sensitive data.',
              'Choose an effect only when supported by the evidence.',
              'If the effect is rollback_deployment or disable_feature,',
              'it must be gated by approval.'
            ].join(' ')
          },
          { role: 'user', content: json(safeInput) }
        ]
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new HttpError(502, 'Model request failed');
    }

    const data = await response.json();
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== 'string') throw new HttpError(502, 'Invalid model response');
    return JSON.parse(content);
  } catch (err) {
    if (err instanceof HttpError) throw err;
    throw new HttpError(502, 'Model unavailable or returned invalid JSON');
  } finally {
    clearTimeout(timer);
  }
}

function normalizePlan(plan, input) {
  if (!plan || typeof plan !== 'object') {
    throw new HttpError(502, 'Invalid incident plan');
  }

  const rootCause = plan.rootCause;
  if (!input.allowedRootCauses.includes(rootCause)) {
    throw new HttpError(502, 'Planner returned an unsupported root cause');
  }

  const evidence = plan.evidence;
  if (!Array.isArray(evidence) || evidence.length < 2 || evidence.length > 4) {
    throw new HttpError(502, 'Evidence must contain 2 to 4 transcript IDs');
  }

  const transcriptIds = new Set(input.transcript.map(x => x.id));
  if (new Set(evidence).size !== evidence.length ||
      evidence.some(x => !transcriptIds.has(x))) {
    throw new HttpError(502, 'Evidence IDs must be distinct transcript IDs');
  }

  if (!Array.isArray(plan.diagnostics) ||
      plan.diagnostics.length < 1 || plan.diagnostics.length > 3) {
    throw new HttpError(502, 'Plan must include 1 to 3 diagnostics');
  }

  for (const d of plan.diagnostics) {
    if (!d || typeof d.toolName !== 'string' ||
        !d.args || typeof d.args !== 'object' || Array.isArray(d.args)) {
      throw new HttpError(502, 'Invalid diagnostic action');
    }
  }

  if (plan.effect != null &&
      (!plan.effect.toolName || typeof plan.effect.toolName !== 'string' ||
       !plan.effect.args || typeof plan.effect.args !== 'object')) {
    throw new HttpError(502, 'Invalid effect action');
  }

  return {
    rootCause,
    evidence,
    summary: typeof plan.summary === 'string' ? plan.summary : '',
    diagnostics: plan.diagnostics,
    effect: plan.effect || null
  };
}

function needsApproval(effect) {
  return effect &&
    ['rollback_deployment', 'disable_feature'].includes(effect.toolName);
}

function createApproval(state) {
  const effect = state.plan.effect;
  const approvalId = id(12);
  const digest = sha(canonical(effect.args));
  state.approval = {
    approvalId,
    actionId: effect.actionId,
    digest,
    status: 'pending',
    receiptId: null,
    nonce: null
  };
  const span = newSpan(state, 'approval_gate', 1, state.agentSpanId);
  attr(span, 'ga5.approval.id', approvalId);
  addSpan(state, span);
}

function finishState(state, status) {
  state.status = status;
  state.updatedAt = iso(now());
}

function advance(state) {
  if (state.actionLog.some(a => a.status === 'pending')) {
    state.status = 'waiting';
    return;
  }

  const diagnostics = state.actionLog.filter(a => a.phase === 'diagnostic');
  if (diagnostics.some(a => a.status !== 'succeeded')) {
    state.effectSuppressed = true;
    finishState(state, 'failed');
    return;
  }

  if (state.approval) {
    if (state.approval.status === 'pending') {
      finishState(state, 'waiting_approval');
      return;
    }
    if (state.approval.status !== 'approved') {
      state.effectSuppressed = true;
      finishState(state, 'failed');
      return;
    }
  }

  if (state.plan.effect && !state.effectDispatched) {
    const effect = state.plan.effect;
    const action = makeAction(state, effect.toolName, effect.args, 'effect');
    effect.actionId = action.id;
    state.effectDispatched = true;
    if (state.approval) {
      action.args = {
        ...action.args,
        approvalId: state.approval.approvalId,
        approvalNonce: state.approval.nonce
      };
    }
    dispatch(state, action);
    state.status = 'waiting';
    return;
  }

  const effects = state.actionLog.filter(a => a.phase === 'effect');
  if (effects.some(a => a.status !== 'succeeded')) {
    finishState(state, 'failed');
  } else {
    finishState(state, 'completed');
  }
}

function responseFor(state, newDispatches = []) {
  return {
    runId: state.runId,
    status: state.status,
    diagnosis: state.plan ? {
      rootCause: state.plan.rootCause,
      evidence: state.plan.evidence,
      summary: state.plan.summary
    } : null,
    dispatches: clone(newDispatches),
    approval: state.approval ? clone(state.approval) : null,
    actionLog: clone(state.actionLog),
    receiptLog: clone(state.receiptLog),
    effectSuppressed: Boolean(state.effectSuppressed),
    trace: buildOtlp(state)
  };
}

function buildOtlp(state) {
  return {
    resourceSpans: [{
      resource: { attributes: [] },
      scopeSpans: [{
        scope: { name: 'ga5-incident-triage' },
        spans: state.spans
      }]
    }]
  };
}

async function createIncident(input, traceHeader) {
  const runId = validateIncident(input);
  const requestHash = sha(canonical(input));
  const existing = load(runId);

  if (existing) {
    if (existing.requestHash !== requestHash) {
      throw new HttpError(409, 'runId already exists with different content');
    }
    return { status: 200, body: existing.initialResponse };
  }

  const context = createTraceContext({ traceparent: traceHeader });
  const state = {
    runId,
    requestHash,
    traceId: context.traceId,
    startedAt: now(),
    updatedAt: iso(now()),
    status: 'planning',
    actionLog: [],
    receiptLog: [],
    receipts: {},
    spans: [],
    dispatches: [],
    effectDispatched: false,
    effectSuppressed: false,
    approval: null
  };

  const serverSpan = rootServerSpan(state, context.parentSpanId);
  addSpan(state, serverSpan);

  const agent = newSpan(state, 'invoke_agent incident-response', 1, serverSpan.spanId);
  state.agentSpanId = agent.spanId;
  addSpan(state, agent);

  const modelSpan = newSpan(state, 'chat incident-plan', 3, agent.spanId);
  attr(modelSpan, 'gen_ai.operation.name', 'chat');
  attr(modelSpan, 'gen_ai.request.model', LLM_MODEL);
  addSpan(state, modelSpan);

  let rawPlan;
  try {
    rawPlan = await callModel(input);
  } catch (err) {
    finishSpan(modelSpan, { code: 2, message: err.message });
    finishSpan(agent, { code: 2, message: 'Planning failed' });
    finishSpan(serverSpan, { code: 2, message: 'Planning failed' });
    state.status = 'failed';
    state.error = err.message;
    state.initialResponse = responseFor(state);
    save(state);
    throw err;
  }

  const plan = normalizePlan(rawPlan, input);
  state.plan = plan;
  finishSpan(modelSpan);
  finishSpan(agent);
  finishSpan(serverSpan);

  for (const d of plan.diagnostics) {
    const action = makeAction(state, d.toolName, d.args, 'diagnostic');
    state.dispatches.push(dispatch(state, action));
  }

  if (plan.diagnostics.length > 1) {
    const join = newSpan(state, 'incident.join', 1, state.agentSpanId);
    join.links = plan.diagnostics.map((_, index) => ({
      traceId: state.traceId,
      spanId: state.actionLog[index].logicalSpanId
    }));
    addSpan(state, join);
  }

  if (needsApproval(plan.effect)) {
    const effectAction = makeAction(state, plan.effect.toolName, plan.effect.args, 'effect');
    plan.effect.actionId = effectAction.id;
    effectAction.status = 'not_dispatched';
    effectAction.args = clone(plan.effect.args);
    state.actionLog.pop();
    createApproval(state);
  }

  state.status = 'waiting';
  state.initialResponse = responseFor(state, state.dispatches);
  save(state);
  return { status: 200, body: state.initialResponse };
}

function validateReceipt(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, 'Expected receipt JSON object');
  }
  if (typeof input.actionId !== 'string' ||
      typeof input.receiptId !== 'string' ||
      typeof input.nonce !== 'string' ||
      typeof input.status !== 'string') {
    throw new HttpError(422, 'Receipt requires actionId, receiptId, nonce and status');
  }
  return input;
}

function postReceipt(runId, receipt) {
  validateReceipt(receipt);
  const state = load(runId);
  if (!state) throw new HttpError(404, 'Incident not found');

  const receiptHash = sha(canonical(receipt));
  const prior = state.receipts[receipt.receiptId];
  if (prior) {
    if (prior.hash !== receiptHash) throw new HttpError(409, 'Receipt ID reused with different content');
    return { status: 200, body: prior.response };
  }

  const action = state.actionLog.find(a => a.id === receipt.actionId);
  const isApproval = state.approval &&
    state.approval.approvalId === receipt.actionId;

  if (!action && !isApproval) throw new HttpError(409, 'Unknown action');
  if (action && action.status !== 'pending') {
    throw new HttpError(409, 'Action is not pending');
  }

  const dispatches = [];

  if (isApproval) {
    if (state.approval.status !== 'pending') {
      throw new HttpError(409, 'Approval is not pending');
    }
    state.approval.receiptId = receipt.receiptId;
    state.approval.nonce = receipt.nonce;
    state.approval.status = receipt.status === 'approved' ? 'approved' : 'rejected';
    state.receiptLog.push(clone(receipt));
    advance(state);
  } else {
    action.receipts.push(clone(receipt));
    state.receiptLog.push(clone(receipt));

    const statusCode = Number(receipt.httpStatus ?? receipt.statusCode ?? 200);
    const failed = receipt.status === 'failed' ||
      receipt.status === 'error' ||
      statusCode >= 400 ||
      receipt.errorType === 'timeout';

    if (statusCode === 503 && action.attempts === 1) {
      const retry = dispatch(state, action, true);
      dispatches.push(retry);
    } else if (failed) {
      action.status = 'failed';
      const lastClient = [...state.spans].reverse().find(
        s => s.name === 'POST tool/' + action.toolName
      );
      if (lastClient) {
        lastClient.status = { code: 2, message: receipt.errorType || String(statusCode) };
        attr(lastClient, 'error.type', receipt.errorType || String(statusCode));
      }
      advance(state);
    } else {
      action.status = 'succeeded';
      advance(state);
    }
  }

  const response = responseFor(state, dispatches);
  state.receipts[receipt.receiptId] = { hash: receiptHash, response };
  save(state);
  return { status: 200, body: response };
}

function getIncident(runId) {
  const state = load(runId);
  if (!state) throw new HttpError(404, 'Incident not found');
  return { status: 200, body: responseFor(state) };
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');

    if (req.method === 'GET' && url.pathname === '/health') {
      return send(res, 200, { status: 'ok' });
    }

    if (req.method === 'POST' && url.pathname === '/v2/incidents') {
      const body = await readBody(req);
      const result = await createIncident(body, req.headers.traceparent);
      return send(res, result.status, result.body);
    }

    const receiptMatch = /^\/v2\/incidents\/([^/]+)\/receipts$/.exec(url.pathname);
    if (req.method === 'POST' && receiptMatch) {
      const runId = decodeURIComponent(receiptMatch[1]);
      const body = await readBody(req);
      const result = postReceipt(runId, body);
      return send(res, result.status, result.body);
    }

    const incidentMatch = /^\/v2\/incidents\/([^/]+)$/.exec(url.pathname);
    if (req.method === 'GET' && incidentMatch) {
      const runId = decodeURIComponent(incidentMatch[1]);
      const result = getIncident(runId);
      return send(res, result.status, result.body);
    }

    return send(res, 404, { error: 'not_found' });
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 500;
    return send(res, status, {
      error: err instanceof HttpError ? err.message : 'internal_error'
    });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`GA5 Q4 server listening on port ${PORT}`);
  console.log(`Data directory: ${DATA_DIR}`);
});
