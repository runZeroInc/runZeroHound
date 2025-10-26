package runzero

// runZero Risk Ranks & Names

const (
	RankNone     = int64(-1)
	RankInfo     = int64(0)
	RankLow      = int64(1)
	RankMedium   = int64(2)
	RankHigh     = int64(3)
	RankCritical = int64(4)
)

const (
	RiskNameNone     = "none"
	RiskNameInfo     = "info"
	RiskNameLow      = "low"
	RiskNameMedium   = "medium"
	RiskNameHigh     = "high"
	RiskNameCritical = "critical"
)

var RiskRankToName = map[int64]string{
	RankNone:     RiskNameNone,
	RankInfo:     RiskNameInfo,
	RankLow:      RiskNameLow,
	RankMedium:   RiskNameMedium,
	RankHigh:     RiskNameHigh,
	RankCritical: RiskNameCritical,
}

var RiskNameToRank = map[string]int64{
	RiskNameNone:     RankNone,
	RiskNameInfo:     RankInfo,
	RiskNameLow:      RankLow,
	RiskNameMedium:   RankMedium,
	RiskNameHigh:     RankHigh,
	RiskNameCritical: RankCritical,
}
