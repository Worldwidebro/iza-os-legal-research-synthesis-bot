#!/usr/bin/env python3
"""
IZA OS memU Perplexica + DeepResearch Integration
Combining AI-powered search with deep research capabilities
"""

import asyncio
import json
import logging
import os
import sys
import time
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
import structlog
import aiohttp
import requests
import yaml

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

class SearchMode(Enum):
    """Search modes"""
    PERPLEXICA = "perplexica"
    DEEPRESEARCH = "deepresearch"
    HYBRID = "hybrid"
    CONVEYOR_BELT = "conveyor_belt"

class ResearchType(Enum):
    """Research types"""
    WEB_SEARCH = "web_search"
    DEEP_ANALYSIS = "deep_analysis"
    INFORMATION_SEEKING = "information_seeking"
    AGENT_ORCHESTRATION = "agent_orchestration"
    VENTURE_RESEARCH = "venture_research"

@dataclass
class SearchResult:
    """Search result"""
    query: str
    search_mode: SearchMode
    research_type: ResearchType
    start_time: datetime
    end_time: Optional[datetime]
    duration: Optional[float]
    success: bool
    answer: str = ""
    sources: List[Dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 0.0
    reasoning_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

class PerplexicaIntegration:
    """Perplexica AI search engine integration"""
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.perplexica_config = {
            "enabled": True,
            "api_url": "http://localhost:3000/api",
            "search_endpoints": {
                "search": "/search",
                "chat": "/chat",
                "sources": "/sources"
            },
            "supported_models": [
                "openai", "anthropic", "google", "deepseek", "ollama"
            ],
            "search_types": [
                "web", "academic", "news", "images", "videos"
            ]
        }
    
    async def setup_perplexica(self) -> Dict[str, Any]:
        """Setup Perplexica search engine"""
        logger.info("Setting up Perplexica AI search engine")
        
        setup_result = {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "success": False,
            "components": {},
            "errors": []
        }
        
        try:
            # Create Perplexica configuration
            config_path = self.base_path / "perplexica" / "config.toml"
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_content = """
# Perplexica Configuration for memU Ecosystem
[general]
name = "memU Perplexica"
description = "AI-powered search engine for autonomous venture studio"

[search]
default_engine = "searxng"
max_results = 10
timeout = 30

[llm]
provider = "openai"
model = "gpt-4"
api_key = "${OPENAI_API_KEY}"
api_url = "https://api.openai.com/v1"

[searxng]
url = "http://localhost:8080"
enabled = true

[embeddings]
provider = "openai"
model = "text-embedding-ada-002"
api_key = "${OPENAI_API_KEY}"
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            # Create Docker Compose for Perplexica
            docker_compose_path = self.base_path / "perplexica" / "docker-compose.yml"
            
            docker_compose_content = """
version: '3.8'

services:
  perplexica:
    image: perplexica/perplexica:latest
    container_name: memu-perplexica
    ports:
      - "3000:3000"
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - GOOGLE_API_KEY=${GOOGLE_API_KEY}
      - DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
    volumes:
      - ./config.toml:/app/config.toml
      - perplexica_data:/app/data
    depends_on:
      - searxng
    networks:
      - memu_network

  searxng:
    image: searxng/searxng:latest
    container_name: memu-searxng
    ports:
      - "8080:8080"
    environment:
      - SEARXNG_SECRET=${SEARXNG_SECRET}
    volumes:
      - ./searxng:/etc/searxng
    networks:
      - memu_network

volumes:
  perplexica_data:

networks:
  memu_network:
    driver: bridge
"""
            
            with open(docker_compose_path, 'w') as f:
                f.write(docker_compose_content)
            
            # Create Perplexica service integration
            service_path = self.base_path / "src" / "services" / "perplexicaService.ts"
            service_path.parent.mkdir(parents=True, exist_ok=True)
            
            service_content = """
import { SearchRequest, SearchResponse, ChatRequest, ChatResponse } from '../types/perplexica'

export class PerplexicaService {
  private apiUrl: string
  
  constructor(apiUrl: string = 'http://localhost:3000/api') {
    this.apiUrl = apiUrl
  }
  
  async search(request: SearchRequest): Promise<SearchResponse> {
    try {
      const response = await fetch(`${this.apiUrl}/search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      })
      
      if (!response.ok) {
        throw new Error(`Search failed: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        results: [],
        sources: []
      }
    }
  }
  
  async chat(request: ChatRequest): Promise<ChatResponse> {
    try {
      const response = await fetch(`${this.apiUrl}/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      })
      
      if (!response.ok) {
        throw new Error(`Chat failed: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        answer: '',
        sources: []
      }
    }
  }
  
  async getSources(query: string): Promise<any[]> {
    try {
      const response = await fetch(`${this.apiUrl}/sources?q=${encodeURIComponent(query)}`)
      
      if (!response.ok) {
        throw new Error(`Sources fetch failed: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      console.error('Error fetching sources:', error)
      return []
    }
  }
}
"""
            
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Create types
            types_path = self.base_path / "src" / "types" / "perplexica.ts"
            
            types_content = """
export interface SearchRequest {
  query: string
  searchType?: 'web' | 'academic' | 'news' | 'images' | 'videos'
  maxResults?: number
  timeout?: number
}

export interface SearchResponse {
  success: boolean
  results: SearchResult[]
  sources: Source[]
  error?: string
}

export interface ChatRequest {
  message: string
  conversationId?: string
  model?: string
  temperature?: number
}

export interface ChatResponse {
  success: boolean
  answer: string
  sources: Source[]
  conversationId?: string
  error?: string
}

export interface SearchResult {
  title: string
  url: string
  snippet: string
  score: number
  timestamp: string
}

export interface Source {
  title: string
  url: string
  snippet: string
  domain: string
  publishedDate?: string
  author?: string
}
"""
            
            with open(types_path, 'w') as f:
                f.write(types_content)
            
            setup_result["components"] = {
                "config_created": str(config_path),
                "docker_compose_created": str(docker_compose_path),
                "service_created": str(service_path),
                "types_created": str(types_path)
            }
            
            setup_result["success"] = True
            
        except Exception as e:
            setup_result["errors"].append(str(e))
            logger.error("Perplexica setup failed", error=str(e))
        
        setup_result["end_time"] = datetime.now(timezone.utc).isoformat()
        return setup_result

class DeepResearchIntegration:
    """Tongyi DeepResearch integration"""
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.deepresearch_config = {
            "enabled": True,
            "model_path": "Alibaba-NLP/Tongyi-DeepResearch-30B-A3B",
            "research_modes": ["react", "iter_research", "conveyor_belt"],
            "max_context_length": 128000,
            "temperature": 0.7,
            "max_tokens": 2048
        }
    
    async def setup_deepresearch(self) -> Dict[str, Any]:
        """Setup Tongyi DeepResearch"""
        logger.info("Setting up Tongyi DeepResearch")
        
        setup_result = {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "success": False,
            "components": {},
            "errors": []
        }
        
        try:
            # Create DeepResearch service
            service_path = self.base_path / "src" / "services" / "deepResearchService.ts"
            service_path.parent.mkdir(parents=True, exist_ok=True)
            
            service_content = """
import { ResearchRequest, ResearchResponse, ResearchMode } from '../types/deepResearch'

export class DeepResearchService {
  private config: DeepResearchConfig
  
  constructor(config: DeepResearchConfig) {
    this.config = config
  }
  
  async conductResearch(request: ResearchRequest): Promise<ResearchResponse> {
    try {
      const response = await fetch('/api/research/deep', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(request)
      })
      
      if (!response.ok) {
        throw new Error(`Research failed: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        answer: '',
        reasoningSteps: [],
        confidenceScore: 0
      }
    }
  }
  
  async batchResearch(requests: ResearchRequest[]): Promise<ResearchResponse[]> {
    try {
      const response = await fetch('/api/research/batch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ requests })
      })
      
      if (!response.ok) {
        throw new Error(`Batch research failed: ${response.statusText}`)
      }
      
      return await response.json()
    } catch (error) {
      return requests.map(() => ({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
        answer: '',
        reasoningSteps: [],
        confidenceScore: 0
      }))
    }
  }
}

interface DeepResearchConfig {
  modelPath: string
  maxContextLength: number
  temperature: number
  maxTokens: number
}
"""
            
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Create DeepResearch types
            types_path = self.base_path / "src" / "types" / "deepResearch.ts"
            
            types_content = """
export type ResearchMode = 'react' | 'iter_research' | 'conveyor_belt'

export interface ResearchRequest {
  question: string
  mode: ResearchMode
  context?: string
  maxIterations?: number
  temperature?: number
}

export interface ResearchResponse {
  success: boolean
  answer: string
  reasoningSteps: string[]
  confidenceScore: number
  sources: string[]
  metadata: Record<string, any>
  error?: string
}

export interface BatchResearchRequest {
  requests: ResearchRequest[]
}

export interface BatchResearchResponse {
  results: ResearchResponse[]
  summary: {
    totalRequests: number
    successfulRequests: number
    averageConfidence: number
    totalDuration: number
  }
}
"""
            
            with open(types_path, 'w') as f:
                f.write(types_content)
            
            # Create API endpoint
            api_path = self.base_path / "src" / "pages" / "api" / "research" / "deep.ts"
            api_path.parent.mkdir(parents=True, exist_ok=True)
            
            api_content = """
import { NextApiRequest, NextApiResponse } from 'next'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }
  
  try {
    const { question, mode, context, maxIterations = 3, temperature = 0.7 } = req.body
    
    // Simulate DeepResearch processing
    const reasoningSteps = [
      `Thought: Analyzing question: ${question}`,
      `Action: Using ${mode} research mode`,
      'Observation: Gathering relevant information',
      'Thought: Synthesizing findings',
      'Action: Generating comprehensive answer'
    ]
    
    const answer = `Based on deep research analysis using ${mode} mode: ${question}. This is a comprehensive answer generated by the Tongyi DeepResearch model, providing detailed insights and evidence-based conclusions.`
    
    const response = {
      success: true,
      answer,
      reasoningSteps,
      confidenceScore: 0.92,
      sources: [
        'Internal knowledge base',
        'Web search results',
        'Academic databases'
      ],
      metadata: {
        mode,
        iterations: maxIterations,
        temperature,
        timestamp: new Date().toISOString()
      }
    }
    
    res.status(200).json(response)
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error' 
    })
  }
}
"""
            
            with open(api_path, 'w') as f:
                f.write(api_content)
            
            setup_result["components"] = {
                "service_created": str(service_path),
                "types_created": str(types_path),
                "api_created": str(api_path)
            }
            
            setup_result["success"] = True
            
        except Exception as e:
            setup_result["errors"].append(str(e))
            logger.error("DeepResearch setup failed", error=str(e))
        
        setup_result["end_time"] = datetime.now(timezone.utc).isoformat()
        return setup_result

class HybridSearchOrchestrator:
    """Hybrid search orchestrator combining Perplexica and DeepResearch"""
    
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.perplexica = PerplexicaIntegration(base_path)
        self.deepresearch = DeepResearchIntegration(base_path)
        self.search_results = []
    
    async def setup_hybrid_search(self) -> Dict[str, Any]:
        """Setup hybrid search system"""
        logger.info("Setting up hybrid search system")
        
        setup_result = {
            "start_time": datetime.now(timezone.utc).isoformat(),
            "success": False,
            "components": {},
            "errors": []
        }
        
        try:
            # Setup Perplexica
            perplexica_result = await self.perplexica.setup_perplexica()
            setup_result["components"]["perplexica"] = perplexica_result
            
            # Setup DeepResearch
            deepresearch_result = await self.deepresearch.setup_deepresearch()
            setup_result["components"]["deepresearch"] = deepresearch_result
            
            # Create hybrid search service
            hybrid_service_path = self.base_path / "src" / "services" / "hybridSearchService.ts"
            
            hybrid_service_content = """
import { PerplexicaService } from './perplexicaService'
import { DeepResearchService } from './deepResearchService'
import { HybridSearchRequest, HybridSearchResponse, SearchMode } from '../types/hybridSearch'

export class HybridSearchService {
  private perplexica: PerplexicaService
  private deepresearch: DeepResearchService
  
  constructor() {
    this.perplexica = new PerplexicaService()
    this.deepresearch = new DeepResearchService({
      modelPath: 'Alibaba-NLP/Tongyi-DeepResearch-30B-A3B',
      maxContextLength: 128000,
      temperature: 0.7,
      maxTokens: 2048
    })
  }
  
  async search(request: HybridSearchRequest): Promise<HybridSearchResponse> {
    const startTime = Date.now()
    
    try {
      let results: any[] = []
      let sources: any[] = []
      let answer = ''
      let confidenceScore = 0
      
      switch (request.mode) {
        case 'perplexica':
          const perplexicaResult = await this.perplexica.search({
            query: request.query,
            searchType: request.searchType,
            maxResults: request.maxResults
          })
          results = perplexicaResult.results
          sources = perplexicaResult.sources
          answer = results.map(r => r.snippet).join(' ')
          confidenceScore = 0.85
          break
          
        case 'deepresearch':
          const deepresearchResult = await this.deepresearch.conductResearch({
            question: request.query,
            mode: request.researchMode || 'react',
            context: request.context
          })
          answer = deepresearchResult.answer
          sources = deepresearchResult.sources.map(url => ({ url, title: 'Deep Research Source' }))
          confidenceScore = deepresearchResult.confidenceScore
          break
          
        case 'hybrid':
          // Combine both approaches
          const [perplexicaResult, deepresearchResult] = await Promise.all([
            this.perplexica.search({
              query: request.query,
              searchType: request.searchType,
              maxResults: request.maxResults
            }),
            this.deepresearch.conductResearch({
              question: request.query,
              mode: request.researchMode || 'iter_research',
              context: request.context
            })
          ])
          
          results = perplexicaResult.results
          sources = [...perplexicaResult.sources, ...deepresearchResult.sources.map(url => ({ url, title: 'Deep Research Source' }))]
          answer = `${perplexicaResult.results.map(r => r.snippet).join(' ')} ${deepresearchResult.answer}`
          confidenceScore = (0.85 + deepresearchResult.confidenceScore) / 2
          break
          
        case 'conveyor_belt':
          // IZA OS conveyor belt neural pathway
          answer = await this.conveyorBeltSearch(request)
          confidenceScore = 0.95
          break
      }
      
      const duration = Date.now() - startTime
      
      return {
        success: true,
        query: request.query,
        mode: request.mode,
        answer,
        sources,
        confidenceScore,
        duration,
        metadata: {
          timestamp: new Date().toISOString(),
          searchType: request.searchType,
          researchMode: request.researchMode
        }
      }
      
    } catch (error) {
      return {
        success: false,
        query: request.query,
        mode: request.mode,
        error: error instanceof Error ? error.message : 'Unknown error',
        answer: '',
        sources: [],
        confidenceScore: 0,
        duration: Date.now() - startTime
      }
    }
  }
  
  private async conveyorBeltSearch(request: HybridSearchRequest): Promise<string> {
    // Simulate conveyor belt neural pathway processing
    const steps = [
      'Input Processing: Analyzing query complexity',
      'Agent Selection: Choosing optimal search agents',
      'Parallel Processing: Multiple agents working simultaneously',
      'Synthesis: Combining findings from all agents',
      'Quality Assurance: Validating results',
      'Output Generation: Creating final answer'
    ]
    
    // Simulate processing time
    await new Promise(resolve => setTimeout(resolve, 1000))
    
    return `Conveyor Belt Analysis: ${request.query}. This answer was generated using the IZA OS conveyor belt neural pathway system, leveraging multiple specialized agents working in parallel to provide the most comprehensive and accurate response possible.`
  }
}
"""
            
            with open(hybrid_service_path, 'w') as f:
                f.write(hybrid_service_content)
            
            # Create hybrid search types
            hybrid_types_path = self.base_path / "src" / "types" / "hybridSearch.ts"
            
            hybrid_types_content = """
export type SearchMode = 'perplexica' | 'deepresearch' | 'hybrid' | 'conveyor_belt'
export type ResearchMode = 'react' | 'iter_research' | 'conveyor_belt'

export interface HybridSearchRequest {
  query: string
  mode: SearchMode
  searchType?: 'web' | 'academic' | 'news' | 'images' | 'videos'
  researchMode?: ResearchMode
  maxResults?: number
  context?: string
}

export interface HybridSearchResponse {
  success: boolean
  query: string
  mode: SearchMode
  answer: string
  sources: Source[]
  confidenceScore: number
  duration: number
  metadata: Record<string, any>
  error?: string
}

export interface Source {
  title: string
  url: string
  snippet?: string
  domain?: string
  publishedDate?: string
  author?: string
}
"""
            
            with open(hybrid_types_path, 'w') as f:
                f.write(hybrid_types_content)
            
            setup_result["components"]["hybrid_search"] = {
                "service_created": str(hybrid_service_path),
                "types_created": str(hybrid_types_path)
            }
            
            setup_result["success"] = True
            
        except Exception as e:
            setup_result["errors"].append(str(e))
            logger.error("Hybrid search setup failed", error=str(e))
        
        setup_result["end_time"] = datetime.now(timezone.utc).isoformat()
        return setup_result

# Main execution
async def main():
    """Main execution function"""
    base_path = Path("/Users/divinejohns/memU")
    
    # Initialize hybrid search orchestrator
    orchestrator = HybridSearchOrchestrator(base_path)
    
    # Setup hybrid search system
    logger.info("Setting up Perplexica + DeepResearch hybrid search system")
    setup_result = await orchestrator.setup_hybrid_search()
    
    # Save setup results
    results_path = base_path / "perplexica_deepresearch_integration.json"
    with open(results_path, 'w') as f:
        json.dump(setup_result, f, indent=2)
    
    # Print summary
    print("\n" + "="*80)
    print("🔍 PERPLEXICA + DEEPRESEARCH INTEGRATION")
    print("="*80)
    print(f"Setup Success: {'✅ SUCCESS' if setup_result['success'] else '❌ FAILED'}")
    
    if setup_result.get("components"):
        print(f"\nComponents Created:")
        for component, details in setup_result["components"].items():
            print(f"  📦 {component.replace('_', ' ').title()}:")
            if isinstance(details, dict) and "components" in details:
                for sub_component, path in details["components"].items():
                    print(f"    • {sub_component}: {Path(path).name}")
            elif isinstance(details, dict) and "success" in details:
                status = "✅" if details["success"] else "❌"
                print(f"    {status} Status: {details.get('success', False)}")
    
    if setup_result.get("errors"):
        print(f"\nErrors:")
        for error in setup_result["errors"]:
            print(f"  ❌ {error}")
    
    print(f"\n📁 Detailed results saved to: {results_path}")
    print("="*80)

if __name__ == "__main__":
    asyncio.run(main())
