from conftest import auth

def test_health(client):
    assert client.get("/health").status_code == 200

def test_api_validation_and_auth(client):
    unauthenticated=client.post("/v1/query",json={"query":"EMEA revenue"})
    assert unauthenticated.status_code==401
    answer=client.post("/v1/query",headers=auth("analyst"),json={"query":"EMEA revenue"})
    assert answer.status_code==200
    assert "$75,000" in answer.json()["answer"]
