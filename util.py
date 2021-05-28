def wrap_result(query):
    results = []
    for row in query:
        results.append(row.wrap())
    return results
