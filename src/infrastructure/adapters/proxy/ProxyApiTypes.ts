export interface ProxyAnalysisRequest {
  networkEvent: {
    destinationUrl: string;
    method: string;
    type: string;
    payloadSize: number;
    payloadFormat: 'json' | 'form' | 'unknown';
    initiatorScript: string;
  };
  behaviorContext: {
    triggerEvent: 'page_unload' | 'form_submit' | 'network_request';
    timeSinceLastInputMs: number;
  };
  recentInputs: Array<{
    fieldType: string;
    length: number;
  }>;
  environment: {
    currentDomain: string;
    externalScripts: string[];
  };
  heuristicContext: {
    verdict: string;
    confidence: number;
    reason: string;
  };
}

export interface ProxyAnalysisResponse {
  verdict: string;
  confidence: number;
  recommendation: string;
  reasonMessage: string;
  analysisDetails?: Record<string, unknown>;
}

export interface ProxyAdapterConfig {
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseDelayMs?: number;
}
