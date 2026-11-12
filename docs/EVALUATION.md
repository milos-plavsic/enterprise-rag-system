# Evaluation scope and plan

The checked-in fixtures/evaluation.json and eval_benchmark.py are authored
synthetic functional regression cases. Success on these cases does not estimate
real-world semantic relevance, production RAG accuracy or business value.
Confidence labels in the original demo were uncalibrated and are removed.

For a production evaluation:

1. Define use cases, cost of errors, permission classes and accepted abstention.
2. Sample realistic, authorised queries from each role and source type.
3. Obtain independent expert labels for expected evidence and answer correctness.
4. Freeze evaluation guidelines and separate development from held-out sets.
5. Compare BM25, dense and hybrid retrieval on Recall@k, MRR, nDCG and latency.
6. Evaluate citation entailment, numerical correctness, complete answers and
   unsupported claims, independently of retrieval ranking.
7. Include denied, unanswerable, contradictory, stale and injection-bearing cases.
8. Treat permission leaks as blocking failures rather than average-score effects.
9. Report subgroup metrics, uncertainty, tail latency, operational cost and
   error categories. Track regressions when sources or models change.
10. Conduct blinded human evaluation and quantify cost per successful task
    and net time saved versus the client's current workflow.

A deployable release requires independent security review, real-data validation,
an approved privacy/data contract, load testing and a documented go/no-go decision.
These external gates are NOT yet met.
