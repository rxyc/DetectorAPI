from fastapi import FastAPI
from pydantic import BaseModel
import pickle
import pandas as pd

app = FastAPI()


class detection(BaseModel):
    ip: int
    length_hostname: int
    shortening_service: int
    nb_at: int
    nb_comma: int
    nb_dollar: int
    nb_semicolon: int
    nb_space: int
    nb_and: int
    nb_dslash: int
    nb_slash: int
    nb_eq: int
    nb_percent: int
    nb_qm: int
    nb_underscore: int
    nb_hyphens: int
    nb_dots: int
    nb_colon: int
    nb_star: int
    nb_or: int
    path_extension: int
    http_in_path: int
    https_token: int
    ratio_digits_host: float
    ratio_digits_url: float
    nb_tilde: int
    phish_hints: int
    tld_in_path: int
    tld_in_subdomain: int
    abnormal_subdomain: int
    nb_redirection: int
    nb_external_redirection: int
    random_domain: int
    punycode: int
    domain_in_brand: int
    brand_in_path: int
    nb_www: int
    nb_com: int
    port: int
    prefix_suffix: int
    nb_subdomains: int
    statistical_report: int
    sus_tld: int

with open('finalized_model.sav', 'rb') as f:
  model = pickle.load(f)

@app.post('/')
async def detect(item:detection):
    df = pd.DataFrame([item.dict().values()], columns=item.dict().keys())
    yhat = model.predict(df)
    return {"prediction:": int(yhat)}
