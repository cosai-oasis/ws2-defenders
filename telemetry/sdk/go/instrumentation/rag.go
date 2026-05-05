package instrumentation

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/girdav01/AITF/sdk/go/semconv"
)

const ragTracerName = "instrumentation.rag"

// RAGInstrumentor traces RAG pipeline operations.
type RAGInstrumentor struct {
	tracer trace.Tracer
}

// NewRAGInstrumentor creates a new RAG instrumentor.
func NewRAGInstrumentor(tp trace.TracerProvider) *RAGInstrumentor {
	if tp == nil {
		tp = otel.GetTracerProvider()
	}
	return &RAGInstrumentor{tracer: tp.Tracer(ragTracerName)}
}

// TracePipeline starts a RAG pipeline span.
func (r *RAGInstrumentor) TracePipeline(ctx context.Context, pipelineName, query string) (context.Context, *RAGPipeline) {
	attrs := []trace.SpanStartOption{
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(semconv.RAGPipelineNameKey.String(pipelineName)),
	}
	if query != "" {
		attrs = append(attrs, trace.WithAttributes(semconv.RAGQueryKey.String(query)))
	}

	ctx, span := r.tracer.Start(ctx, fmt.Sprintf("rag.pipeline %s", pipelineName), attrs...)
	return ctx, &RAGPipeline{span: span, tracer: r.tracer, pipelineName: pipelineName}
}

// TraceRetrieve starts a standalone retrieval span.
func (r *RAGInstrumentor) TraceRetrieve(ctx context.Context, database string, topK int) (context.Context, *RetrievalSpan) {
	ctx, span := r.tracer.Start(ctx,
		fmt.Sprintf("rag.retrieve %s", database),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.RAGPipelineStageKey.String(semconv.RAGStageRetrieve),
			semconv.RAGRetrieveDatabaseKey.String(database),
			semconv.RAGRetrieveTopKKey.Int(topK),
		),
	)
	return ctx, &RetrievalSpan{span: span}
}

// RAGPipeline manages child spans within a RAG pipeline.
type RAGPipeline struct {
	span         trace.Span
	tracer       trace.Tracer
	pipelineName string
}

// Retrieve starts a retrieval child span.
func (p *RAGPipeline) Retrieve(ctx context.Context, database string, topK int) (context.Context, *RetrievalSpan) {
	ctx, span := p.tracer.Start(ctx,
		fmt.Sprintf("rag.retrieve %s", database),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.RAGPipelineStageKey.String(semconv.RAGStageRetrieve),
			semconv.RAGPipelineNameKey.String(p.pipelineName),
			semconv.RAGRetrieveDatabaseKey.String(database),
			semconv.RAGRetrieveTopKKey.Int(topK),
		),
	)
	return ctx, &RetrievalSpan{span: span}
}

// Rerank starts a reranking child span.
func (p *RAGPipeline) Rerank(ctx context.Context, model string) (context.Context, *RerankSpan) {
	ctx, span := p.tracer.Start(ctx,
		fmt.Sprintf("rag.rerank %s", model),
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			semconv.RAGPipelineStageKey.String(semconv.RAGStageRerank),
			semconv.RAGRerankModelKey.String(model),
		),
	)
	return ctx, &RerankSpan{span: span}
}

// SetQuality sets RAG quality metrics on the pipeline span.
func (p *RAGPipeline) SetQuality(contextRelevance, faithfulness, groundedness float64) {
	p.span.SetAttributes(
		semconv.RAGQualityContextRelevanceKey.Float64(contextRelevance),
		semconv.RAGQualityFaithfulnessKey.Float64(faithfulness),
		semconv.RAGQualityGroundednessKey.Float64(groundedness),
	)
}

// End completes the pipeline span.
func (p *RAGPipeline) End(err error) {
	if err != nil {
		p.span.SetStatus(codes.Error, err.Error())
	} else {
		p.span.SetStatus(codes.Ok, "")
	}
	p.span.End()
}

// RetrievalSpan manages a retrieval span.
type RetrievalSpan struct{ span trace.Span }

// SetResults sets retrieval result attributes.
func (r *RetrievalSpan) SetResults(count int, minScore, maxScore float64) {
	r.span.SetAttributes(
		semconv.RAGRetrieveResultsCountKey.Int(count),
		semconv.RAGRetrieveMinScoreKey.Float64(minScore),
		semconv.RAGRetrieveMaxScoreKey.Float64(maxScore),
	)
}

// End completes the retrieval span.
func (r *RetrievalSpan) End(err error) {
	if err != nil {
		r.span.SetStatus(codes.Error, err.Error())
	} else {
		r.span.SetStatus(codes.Ok, "")
	}
	r.span.End()
}

// RerankSpan manages a reranking span.
type RerankSpan struct{ span trace.Span }

// SetResults sets reranking result counts.
func (r *RerankSpan) SetResults(inputCount, outputCount int) {
	r.span.SetAttributes(
		semconv.RAGRerankInputCountKey.Int(inputCount),
		semconv.RAGRerankOutputCountKey.Int(outputCount),
	)
}

// End completes the rerank span.
func (r *RerankSpan) End(err error) {
	if err != nil {
		r.span.SetStatus(codes.Error, err.Error())
	} else {
		r.span.SetStatus(codes.Ok, "")
	}
	r.span.End()
}
