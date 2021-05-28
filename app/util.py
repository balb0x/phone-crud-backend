def wrap_result(query):
    """
    Wraps a given MongoAlchemy result query in a simple Array so
    it can be transformed in a JSON object
    :param query:
    :return:
    """
    results = []
    for row in query:
        results.append(row.wrap())
    return results
