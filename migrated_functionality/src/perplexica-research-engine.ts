/**
 * IZA OS Perplexica Integration for Deep Research
 * Advanced AI-powered research capabilities for the IZA OS ecosystem
 */

import { IZAOSApiClient } from './client';
import { EventEmitter } from 'events';

export interface PerplexicaConfig {
  api_url: string;
  api_key: string;
  search_engines: string[];
  max_results: number;
  timeout: number;
  enable_caching: boolean;
  cache_ttl: number;
}

export interface ResearchQuery {
  id: string;
  query: string;
  context: string;
  research_type: 'market_analysis' | 'competitor_analysis' | 'technology_research' | 'financial_research' | 'regulatory_research';
  depth_level: 'surface' | 'deep' | 'comprehensive';
  sources: string[];
  filters: ResearchFilters;
  created_at: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
}

export interface ResearchFilters {
  date_range?: {
    start: string;
    end: string;
  };
  language?: string;
  region?: string;
  domain_whitelist?: string[];
  domain_blacklist?: string[];
  content_type?: string[];
  credibility_threshold?: number;
}

export interface ResearchResult {
  id: string;
  query_id: string;
  source: string;
  title: string;
  url: string;
  content: string;
  summary: string;
  relevance_score: number;
  credibility_score: number;
  published_date: string;
  author?: string;
  metadata: Record<string, any>;
  extracted_insights: string[];
  key_findings: string[];
}

export interface ResearchReport {
  id: string;
  query_id: string;
  title: string;
  executive_summary: string;
  key_findings: string[];
  detailed_analysis: string;
  recommendations: string[];
  sources: ResearchResult[];
  confidence_score: number;
  generated_at: string;
  metadata: Record<string, any>;
}

export interface DeepResearchSession {
  id: string;
  company_id: string;
  research_queries: ResearchQuery[];
  reports: ResearchReport[];
  insights: ResearchInsight[];
  status: 'active' | 'completed' | 'paused';
  created_at: string;
  updated_at: string;
}

export interface ResearchInsight {
  id: string;
  session_id: string;
  insight_type: 'market_trend' | 'competitor_move' | 'technology_shift' | 'regulatory_change' | 'opportunity' | 'threat';
  title: string;
  description: string;
  confidence: number;
  impact_level: 'low' | 'medium' | 'high' | 'critical';
  actionable: boolean;
  recommendations: string[];
  sources: string[];
  generated_at: string;
}

export class PerplexicaResearchEngine extends EventEmitter {
  private apiClient: IZAOSApiClient;
  private config: PerplexicaConfig;
  private activeSessions: Map<string, DeepResearchSession> = new Map();
  private researchCache: Map<string, ResearchResult[]> = new Map();

  constructor(apiClient: IZAOSApiClient, config: PerplexicaConfig) {
    super();
    this.apiClient = apiClient;
    this.config = config;
  }

  /**
   * Initialize deep research session for company creation
   */
  async initializeResearchSession(companyId: string, sector: string, productType: string): Promise<DeepResearchSession> {
    const session: DeepResearchSession = {
      id: `research_${companyId}_${Date.now()}`,
      company_id: companyId,
      research_queries: [],
      reports: [],
      insights: [],
      status: 'active',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    // Generate initial research queries based on sector and product type
    const initialQueries = await this.generateInitialQueries(sector, productType);
    session.research_queries = initialQueries;

    this.activeSessions.set(session.id, session);
    this.emit('session_initialized', session);

    return session;
  }

  /**
   * Execute comprehensive research for a specific query
   */
  async executeResearch(query: ResearchQuery): Promise<ResearchReport> {
    try {
      query.status = 'processing';
      this.emit('research_started', query);

      // Check cache first
      const cacheKey = this.generateCacheKey(query);
      if (this.config.enable_caching && this.researchCache.has(cacheKey)) {
        const cachedResults = this.researchCache.get(cacheKey)!;
        return await this.generateReport(query, cachedResults);
      }

      // Execute multi-engine search
      const searchResults = await this.executeMultiEngineSearch(query);
      
      // Cache results
      if (this.config.enable_caching) {
        this.researchCache.set(cacheKey, searchResults);
      }

      // Generate comprehensive report
      const report = await this.generateReport(query, searchResults);
      
      query.status = 'completed';
      this.emit('research_completed', { query, report });

      return report;

    } catch (error) {
      query.status = 'failed';
      this.emit('research_failed', { query, error });
      throw error;
    }
  }

  /**
   * Execute multi-engine search using Perplexica
   */
  private async executeMultiEngineSearch(query: ResearchQuery): Promise<ResearchResult[]> {
    const results: ResearchResult[] = [];

    for (const engine of this.config.search_engines) {
      try {
        const engineResults = await this.searchWithEngine(engine, query);
        results.push(...engineResults);
      } catch (error) {
        console.warn(`Search engine ${engine} failed:`, error);
      }
    }

    // Deduplicate and rank results
    return this.deduplicateAndRank(results, query);
  }

  /**
   * Search using specific engine
   */
  private async searchWithEngine(engine: string, query: ResearchQuery): Promise<ResearchResult[]> {
    const searchParams = {
      query: query.query,
      context: query.context,
      engine: engine,
      max_results: this.config.max_results,
      filters: query.filters
    };

    // Use IZA OS orchestration to call Perplexica API
    const response = await this.apiClient.runAVS478Inference({
      model_id: 'perplexica_search',
      input_data: searchParams,
      parameters: {
        timeout: this.config.timeout,
        enable_streaming: true
      }
    });

    return this.parseSearchResults(response.data.output, engine);
  }

  /**
   * Generate comprehensive research report
   */
  private async generateReport(query: ResearchQuery, results: ResearchResult[]): Promise<ResearchReport> {
    // Use AI to analyze results and generate report
    const analysisPrompt = {
      query: query.query,
      context: query.context,
      research_type: query.research_type,
      results: results,
      requirements: {
        include_executive_summary: true,
        include_key_findings: true,
        include_detailed_analysis: true,
        include_recommendations: true,
        max_length: 5000
      }
    };

    const analysisResponse = await this.apiClient.runAVS478Inference({
      model_id: 'research_analyzer',
      input_data: analysisPrompt,
      parameters: {
        temperature: 0.3,
        max_tokens: 6000
      }
    });

    const report: ResearchReport = {
      id: `report_${query.id}_${Date.now()}`,
      query_id: query.id,
      title: this.generateReportTitle(query),
      executive_summary: analysisResponse.data.output.executive_summary,
      key_findings: analysisResponse.data.output.key_findings,
      detailed_analysis: analysisResponse.data.output.detailed_analysis,
      recommendations: analysisResponse.data.output.recommendations,
      sources: results,
      confidence_score: this.calculateConfidenceScore(results),
      generated_at: new Date().toISOString(),
      metadata: {
        research_type: query.research_type,
        depth_level: query.depth_level,
        sources_count: results.length,
        processing_time: Date.now()
      }
    };

    return report;
  }

  /**
   * Generate initial research queries for company creation
   */
  private async generateInitialQueries(sector: string, productType: string): Promise<ResearchQuery[]> {
    const queries: ResearchQuery[] = [];

    // Market Analysis Query
    queries.push({
      id: `market_analysis_${Date.now()}`,
      query: `Market analysis for ${sector} ${productType} industry trends, growth, and opportunities`,
      context: `Analyzing market opportunities for a new ${sector} ${productType} company`,
      research_type: 'market_analysis',
      depth_level: 'comprehensive',
      sources: ['industry_reports', 'market_research', 'financial_data'],
      filters: {
        date_range: {
          start: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString()
        },
        credibility_threshold: 0.8
      },
      created_at: new Date().toISOString(),
      status: 'pending'
    });

    // Competitor Analysis Query
    queries.push({
      id: `competitor_analysis_${Date.now()}`,
      query: `Competitor analysis for ${sector} ${productType} companies, their strategies, and market positioning`,
      context: `Understanding competitive landscape for ${sector} ${productType} market`,
      research_type: 'competitor_analysis',
      depth_level: 'deep',
      sources: ['company_websites', 'press_releases', 'financial_reports', 'news'],
      filters: {
        date_range: {
          start: new Date(Date.now() - 180 * 24 * 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString()
        },
        credibility_threshold: 0.7
      },
      created_at: new Date().toISOString(),
      status: 'pending'
    });

    // Technology Research Query
    queries.push({
      id: `technology_research_${Date.now()}`,
      query: `Technology trends and innovations in ${sector} ${productType} development`,
      context: `Researching latest technologies for ${sector} ${productType} platform`,
      research_type: 'technology_research',
      depth_level: 'deep',
      sources: ['tech_news', 'research_papers', 'patent_database', 'developer_communities'],
      filters: {
        date_range: {
          start: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString()
        },
        credibility_threshold: 0.8
      },
      created_at: new Date().toISOString(),
      status: 'pending'
    });

    // Financial Research Query
    queries.push({
      id: `financial_research_${Date.now()}`,
      query: `Financial analysis and funding trends for ${sector} ${productType} startups and companies`,
      context: `Understanding funding landscape for ${sector} ${productType} ventures`,
      research_type: 'financial_research',
      depth_level: 'comprehensive',
      sources: ['financial_reports', 'funding_database', 'investor_news', 'market_data'],
      filters: {
        date_range: {
          start: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(),
          end: new Date().toISOString()
        },
        credibility_threshold: 0.9
      },
      created_at: new Date().toISOString(),
      status: 'pending'
    });

    // Regulatory Research Query
    queries.push({
      id: `regulatory_research_${Date.now()}`,
      query: `Regulatory requirements and compliance standards for ${sector} ${productType} companies`,
      context: `Understanding regulatory landscape for ${sector} ${productType} business`,
      research_type: 'regulatory_research',
      depth_level: 'comprehensive',
      sources: ['government_sites', 'regulatory_documents', 'compliance_guides', 'legal_analysis'],
      filters: {
        credibility_threshold: 0.95
      },
      created_at: new Date().toISOString(),
      status: 'pending'
    });

    return queries;
  }

  /**
   * Generate insights from research reports
   */
  async generateInsights(sessionId: string): Promise<ResearchInsight[]> {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Research session not found');

    const insights: ResearchInsight[] = [];

    // Analyze all reports to generate insights
    for (const report of session.reports) {
      const reportInsights = await this.analyzeReportForInsights(report);
      insights.push(...reportInsights);
    }

    // Cross-reference insights for patterns
    const crossReferencedInsights = await this.crossReferenceInsights(insights);
    
    session.insights = crossReferencedInsights;
    session.updated_at = new Date().toISOString();

    this.emit('insights_generated', { session, insights: crossReferencedInsights });

    return crossReferencedInsights;
  }

  /**
   * Analyze individual report for insights
   */
  private async analyzeReportForInsights(report: ResearchReport): Promise<ResearchInsight[]> {
    const insights: ResearchInsight[] = [];

    // Use AI to extract insights from report
    const insightPrompt = {
      report: report,
      insight_types: ['market_trend', 'competitor_move', 'technology_shift', 'regulatory_change', 'opportunity', 'threat'],
      requirements: {
        actionable_only: true,
        confidence_threshold: 0.7,
        max_insights_per_type: 3
      }
    };

    const insightResponse = await this.apiClient.runAVS478Inference({
      model_id: 'insight_extractor',
      input_data: insightPrompt,
      parameters: {
        temperature: 0.2,
        max_tokens: 4000
      }
    });

    for (const insightData of insightResponse.data.output.insights) {
      const insight: ResearchInsight = {
        id: `insight_${report.id}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        session_id: report.query_id,
        insight_type: insightData.type,
        title: insightData.title,
        description: insightData.description,
        confidence: insightData.confidence,
        impact_level: insightData.impact_level,
        actionable: insightData.actionable,
        recommendations: insightData.recommendations,
        sources: [report.id],
        generated_at: new Date().toISOString()
      };
      insights.push(insight);
    }

    return insights;
  }

  /**
   * Cross-reference insights for patterns and connections
   */
  private async crossReferenceInsights(insights: ResearchInsight[]): Promise<ResearchInsight[]> {
    const crossReferencePrompt = {
      insights: insights,
      requirements: {
        find_patterns: true,
        identify_connections: true,
        merge_similar: true,
        boost_confidence: true
      }
    };

    const crossReferenceResponse = await this.apiClient.runAVS478Inference({
      model_id: 'insight_cross_referencer',
      input_data: crossReferencePrompt,
      parameters: {
        temperature: 0.1,
        max_tokens: 3000
      }
    });

    return crossReferenceResponse.data.output.refined_insights;
  }

  /**
   * Generate final research summary for company creation
   */
  async generateCompanyResearchSummary(sessionId: string): Promise<any> {
    const session = this.activeSessions.get(sessionId);
    if (!session) throw new Error('Research session not found');

    const summaryPrompt = {
      session: session,
      requirements: {
        include_executive_summary: true,
        include_market_opportunity: true,
        include_competitive_landscape: true,
        include_technology_recommendations: true,
        include_funding_strategy: true,
        include_regulatory_considerations: true,
        include_risk_assessment: true,
        include_actionable_next_steps: true
      }
    };

    const summaryResponse = await this.apiClient.runAVS478Inference({
      model_id: 'research_summarizer',
      input_data: summaryPrompt,
      parameters: {
        temperature: 0.3,
        max_tokens: 8000
      }
    });

    const summary = {
      session_id: sessionId,
      company_id: session.company_id,
      generated_at: new Date().toISOString(),
      ...summaryResponse.data.output
    };

    session.status = 'completed';
    session.updated_at = new Date().toISOString();

    this.emit('summary_generated', summary);

    return summary;
  }

  // Helper methods
  private generateCacheKey(query: ResearchQuery): string {
    return `${query.query}_${query.research_type}_${query.depth_level}_${JSON.stringify(query.filters)}`;
  }

  private parseSearchResults(results: any, engine: string): ResearchResult[] {
    return results.map((result: any) => ({
      id: `result_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      query_id: '',
      source: engine,
      title: result.title,
      url: result.url,
      content: result.content,
      summary: result.summary,
      relevance_score: result.relevance_score || 0.5,
      credibility_score: result.credibility_score || 0.5,
      published_date: result.published_date || new Date().toISOString(),
      author: result.author,
      metadata: result.metadata || {},
      extracted_insights: result.extracted_insights || [],
      key_findings: result.key_findings || []
    }));
  }

  private deduplicateAndRank(results: ResearchResult[], query: ResearchQuery): ResearchResult[] {
    // Remove duplicates based on URL
    const uniqueResults = results.filter((result, index, self) => 
      index === self.findIndex(r => r.url === result.url)
    );

    // Sort by relevance and credibility scores
    return uniqueResults
      .sort((a, b) => {
        const scoreA = (a.relevance_score + a.credibility_score) / 2;
        const scoreB = (b.relevance_score + b.credibility_score) / 2;
        return scoreB - scoreA;
      })
      .slice(0, this.config.max_results);
  }

  private generateReportTitle(query: ResearchQuery): string {
    const typeMap = {
      'market_analysis': 'Market Analysis',
      'competitor_analysis': 'Competitor Analysis',
      'technology_research': 'Technology Research',
      'financial_research': 'Financial Research',
      'regulatory_research': 'Regulatory Research'
    };

    return `${typeMap[query.research_type]} Report: ${query.query}`;
  }

  private calculateConfidenceScore(results: ResearchResult[]): number {
    if (results.length === 0) return 0;

    const avgRelevance = results.reduce((sum, r) => sum + r.relevance_score, 0) / results.length;
    const avgCredibility = results.reduce((sum, r) => sum + r.credibility_score, 0) / results.length;
    const sourceDiversity = new Set(results.map(r => r.source)).size / results.length;

    return (avgRelevance + avgCredibility + sourceDiversity) / 3;
  }

  // Public API methods
  public getSession(sessionId: string): DeepResearchSession | undefined {
    return this.activeSessions.get(sessionId);
  }

  public getAllSessions(): DeepResearchSession[] {
    return Array.from(this.activeSessions.values());
  }

  public getSessionInsights(sessionId: string): ResearchInsight[] {
    const session = this.activeSessions.get(sessionId);
    return session?.insights || [];
  }

  public updateConfig(newConfig: Partial<PerplexicaConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }
}

export default PerplexicaResearchEngine;
