# Project Roadmap: OSINT Recon & Social Network Attack Surface Mapper

## Vision
A modular red team OSINT tool that maps an organization's social network attack surface, scores exposure risk, and generates professional assessment reports.

---

## Phase 1: Foundation (Weeks 1-2)
**Goal:** Core architecture, first working collector, basic graph

- [ ] Set up virtual environment and install dependencies
- [ ] Implement GitHub collector (API calls, member enumeration, commit email scraping)
- [ ] Build basic NetworkX graph from GitHub org member data
- [ ] Add unit tests for discovery engine and graph builder
- [ ] Set up CI/CD with GitHub Actions (linting, tests)

**Milestone:** `python main.py --target "org" --collectors github` produces a basic relationship graph

---

## Phase 2: Data Collection Expansion (Weeks 3-4)
**Goal:** Multiple data sources feeding into the graph

- [ ] Implement Shodan collector (infrastructure mapping)
- [ ] Implement HIBP collector (breach exposure checking)
- [ ] Implement Web Scraper collector (corporate site, document metadata)
- [ ] Add async rate limiting across all collectors
- [ ] Build data normalization layer (dedup people across sources)
- [ ] Add Twitter/X public data collection (if API accessible)

**Milestone:** Full multi-source discovery populates a rich organization model

---

## Phase 3: Graph Analysis & Scoring (Weeks 5-6)
**Goal:** Meaningful intelligence from the collected data

- [ ] Implement all centrality metrics (degree, betweenness, closeness, PageRank)
- [ ] Build composite target scoring algorithm
- [ ] Implement attack path finder (shortest paths to high-value targets)
- [ ] Build exposure scoring engine (breach, social, infra, metadata weights)
- [ ] Add Gephi export for external visualization
- [ ] Create interactive pyvis graph visualization

**Milestone:** Tool identifies top 10 high-value targets with scored attack paths

---

## Phase 4: Reporting (Weeks 7-8)
**Goal:** Professional red team deliverables

- [ ] Design PDF report template (executive summary, findings, recommendations)
- [ ] Implement PDF generation with WeasyPrint
- [ ] Build interactive HTML report with embedded vis.js graph
- [ ] Add JSON export for tool integration
- [ ] Include remediation recommendations engine
- [ ] Generate sample report with synthetic data for portfolio

**Milestone:** Full assessment produces a professional PDF report ready for client delivery

---

## Phase 5: Polish & Portfolio (Weeks 9-10)
**Goal:** GitHub-ready, portfolio-worthy project

- [ ] Write comprehensive README with architecture diagram
- [ ] Create demo video / GIF showing tool in action
- [ ] Write blog post / case study walkthrough
- [ ] Add Docker support for easy setup
- [ ] Perform security review (no accidental key exposure)
- [ ] Add ethical use disclaimer and responsible disclosure guidance
- [ ] Tag v1.0.0 release

**Milestone:** Published GitHub repo with blog post ready for portfolio

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   main.py (CLI)                  │
├─────────────────────────────────────────────────┤
│              Discovery Engine                    │
│  ┌──────────┬──────────┬────────┬────────────┐  │
│  │  GitHub   │  Shodan  │  HIBP  │ WebScraper │  │
│  │Collector  │Collector │Collect │ Collector  │  │
│  └──────────┴──────────┴────────┴────────────┘  │
├─────────────────────────────────────────────────┤
│           Network Graph Builder                  │
│  ┌──────────────────────────────────────┐       │
│  │  NetworkX Graph + Centrality Metrics  │       │
│  │  Attack Path Analysis                 │       │
│  │  Gephi/pyvis Export                   │       │
│  └──────────────────────────────────────┘       │
├─────────────────────────────────────────────────┤
│            Exposure Scorer                       │
│  ┌──────────────────────────────────────┐       │
│  │  Breach Score (30%)                   │       │
│  │  Social Media Score (25%)             │       │
│  │  Infrastructure Score (25%)           │       │
│  │  Metadata Score (20%)                 │       │
│  └──────────────────────────────────────┘       │
├─────────────────────────────────────────────────┤
│            Report Generator                      │
│  ┌──────────┬──────────┬────────────────┐       │
│  │   PDF    │   HTML   │     JSON       │       │
│  │ Report   │ Report   │    Export      │       │
│  └──────────┴──────────┴────────────────┘       │
└─────────────────────────────────────────────────┘
```

## Tech Stack
- **Language:** Python 3.11+
- **Graph Analysis:** NetworkX, pyvis, Gephi (GEXF export)
- **Data Storage:** Neo4j (stretch goal), JSON/SQLite
- **APIs:** GitHub REST API, Shodan, HIBP, BeautifulSoup
- **Reporting:** WeasyPrint (PDF), Jinja2 (HTML), Plotly (charts)
- **Testing:** pytest, pytest-asyncio
- **CI/CD:** GitHub Actions
- **Packaging:** Docker (stretch goal)
