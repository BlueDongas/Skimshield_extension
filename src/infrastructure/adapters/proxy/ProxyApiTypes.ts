export interface ProxyAnalysisRequest {
  networkEvent: {
    destinationUrl: string;
    method: string;
    type: string;
    payloadSize: number;
    payloadFormat: 'JSON' | 'FORM_DATA' | 'BASE64' | 'UNKNOWN';
    initiatorScript: string;
  };
  behaviorContext: {
    triggerEvent: 'click' | 'submit' | 'blur' | 'timer' | 'unknown';
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
  analysisDetails?: {
    suspiciousFactors: string[];
    safeFactors: string[];
  };
}

export interface ProxyAdapterConfig {
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseDelayMs?: number;
}
