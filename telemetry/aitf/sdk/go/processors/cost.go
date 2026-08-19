package processors

import (
	"strings"
	"sync"
)

// ModelPricing holds per-1M-token pricing for a model.
type ModelPricing struct {
	InputPer1M  float64
	OutputPer1M float64
}

// CostResult holds the calculated cost for an operation.
type CostResult struct {
	InputCost  float64
	OutputCost float64
	TotalCost  float64
	Currency   string
}

// maxTokens is the maximum reasonable token count per request.
const maxTokens = 10_000_000

// CostProcessor calculates costs for AI operations.
type CostProcessor struct {
	pricing     map[string]ModelPricing
	budgetLimit float64
	totalCost   float64
	currency    string
	mu          sync.RWMutex
}

// NewCostProcessor creates a new cost processor.
func NewCostProcessor(budgetLimit float64, customPricing map[string]ModelPricing) *CostProcessor {
	pricing := map[string]ModelPricing{
		"gpt-4o":                     {InputPer1M: 2.50, OutputPer1M: 10.00},
		"gpt-4o-mini":                {InputPer1M: 0.15, OutputPer1M: 0.60},
		"gpt-4-turbo":                {InputPer1M: 10.00, OutputPer1M: 30.00},
		"gpt-3.5-turbo":              {InputPer1M: 0.50, OutputPer1M: 1.50},
		"o1":                         {InputPer1M: 15.00, OutputPer1M: 60.00},
		"o3-mini":                    {InputPer1M: 1.10, OutputPer1M: 4.40},
		"claude-opus-4-6":            {InputPer1M: 15.00, OutputPer1M: 75.00},
		"claude-sonnet-4-5-20250929": {InputPer1M: 3.00, OutputPer1M: 15.00},
		"claude-haiku-4-5-20251001":  {InputPer1M: 0.80, OutputPer1M: 4.00},
		"claude-3-5-sonnet-20241022": {InputPer1M: 3.00, OutputPer1M: 15.00},
		"gemini-2.0-flash":           {InputPer1M: 0.10, OutputPer1M: 0.40},
		"gemini-1.5-pro":             {InputPer1M: 1.25, OutputPer1M: 5.00},
		"mistral-large-latest":       {InputPer1M: 2.00, OutputPer1M: 6.00},
		"command-r-plus":             {InputPer1M: 2.50, OutputPer1M: 10.00},
		"text-embedding-3-small":     {InputPer1M: 0.02, OutputPer1M: 0.00},
		"text-embedding-3-large":     {InputPer1M: 0.13, OutputPer1M: 0.00},
	}

	for k, v := range customPricing {
		pricing[k] = v
	}

	return &CostProcessor{
		pricing:     pricing,
		budgetLimit: budgetLimit,
		currency:    "USD",
	}
}

// CalculateCost computes cost for a model and token count.
func (c *CostProcessor) CalculateCost(model string, inputTokens, outputTokens int) *CostResult {
	// Validate token counts
	if inputTokens < 0 {
		inputTokens = 0
	}
	if inputTokens > maxTokens {
		inputTokens = maxTokens
	}
	if outputTokens < 0 {
		outputTokens = 0
	}
	if outputTokens > maxTokens {
		outputTokens = maxTokens
	}

	p := c.getPricing(model)
	if p == nil {
		return nil
	}

	inputCost := (float64(inputTokens) / 1_000_000) * p.InputPer1M
	outputCost := (float64(outputTokens) / 1_000_000) * p.OutputPer1M

	result := &CostResult{
		InputCost:  inputCost,
		OutputCost: outputCost,
		TotalCost:  inputCost + outputCost,
		Currency:   c.currency,
	}

	c.mu.Lock()
	c.totalCost += result.TotalCost
	c.mu.Unlock()

	return result
}

// TotalCost returns the accumulated total cost.
func (c *CostProcessor) TotalCost() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalCost
}

// BudgetExceeded returns true if budget limit has been exceeded.
func (c *CostProcessor) BudgetExceeded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.budgetLimit > 0 && c.totalCost > c.budgetLimit
}

// BudgetRemaining returns the remaining budget.
func (c *CostProcessor) BudgetRemaining() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.budgetLimit <= 0 {
		return -1
	}
	remaining := c.budgetLimit - c.totalCost
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (c *CostProcessor) getPricing(model string) *ModelPricing {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if p, ok := c.pricing[model]; ok {
		return &p
	}
	// Try prefix match
	for key, p := range c.pricing {
		if strings.HasPrefix(model, key) {
			return &p
		}
	}
	return nil
}
