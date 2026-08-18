"""OAuth broker for Claude MCP users and Basecamp identities (Vercel KV backed)."""
import asyncio, hashlib, json, os, secrets, time
from urllib.parse import urlencode, quote
from cryptography.fernet import Fernet
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from mcp.server.auth.provider import AccessToken, AuthorizationCode, AuthorizationParams, RefreshToken, TokenError, ProviderTokenVerifier, construct_redirect_uri
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from basecamp_oauth import BasecampOAuth

TTL_CODE=300; ACCESS_TTL=3600; REFRESH_TTL=60*60*24*30

def _key(kind, value): return 'basecamp-mcp:' + kind + ':' + hashlib.sha256(value.encode()).hexdigest()
class KV:
 def __init__(self):
  self.url=os.environ['KV_REST_API_URL'].rstrip('/'); self.token=os.environ['KV_REST_API_TOKEN']
 def _request(self, method, path, body=None):
  import requests
  r=requests.request(method, self.url+path, headers={'Authorization':'Bearer '+self.token,'Content-Type':'application/json'}, data=json.dumps(body) if body is not None else None, timeout=10); r.raise_for_status(); return r.json().get('result')
 async def get(self,k):
  value=await asyncio.to_thread(self._request,'GET','/get/'+k)
  return json.loads(value) if value else None
 async def set(self,k,v,ttl=None):
  path='/set/'+quote(k,safe='')+'/'+quote(json.dumps(v,separators=(',',':')),safe='')
  if ttl: path+='/EX/'+str(ttl)
  await asyncio.to_thread(self._request,'POST',path)
 async def delete(self,k): await asyncio.to_thread(self._request,'POST','/del/'+k)

class BasecampOAuthProvider:
 def __init__(self):
  self.kv=KV(); self.fernet=Fernet(os.environ['BASECAMP_MCP_ENCRYPTION_KEY'].encode()); self.callback_url=os.environ['BASECAMP_MULTIUSER_REDIRECT_URI']
 def _crypt(self,d): return self.fernet.encrypt(json.dumps(d).encode()).decode()
 def _decrypt(self,s): return json.loads(self.fernet.decrypt(s.encode()))
 async def get_client(self, client_id):
  data=await self.kv.get(_key('client',client_id)); return OAuthClientInformationFull.model_validate(data) if data else None
 async def register_client(self, client): await self.kv.set(_key('client',client.client_id),client.model_dump(mode='json'))
 async def authorize(self, client, params: AuthorizationParams):
  state=secrets.token_urlsafe(32)
  await self.kv.set(_key('pending',state), {'client_id':client.client_id,'redirect_uri':str(params.redirect_uri),'explicit':params.redirect_uri_provided_explicitly,'challenge':params.code_challenge,'scopes':params.scopes or [],'resource':params.resource,'client_state':params.state}, TTL_CODE)
  q={'response_type':'code','client_id':os.environ.get('BASECAMP_MULTIUSER_CLIENT_ID',os.environ['BASECAMP_CLIENT_ID']),'redirect_uri':self.callback_url,'state':state}
  return 'https://launchpad.37signals.com/authorization/new?'+urlencode(q)
 async def callback(self, request: Request):
  state=request.query_params.get('state'); code=request.query_params.get('code'); pending=await self.kv.get(_key('pending',state or ''))
  if not state or not code or not pending: return HTMLResponse('Authorization expired. Return to Claude and try again.',400)
  await self.kv.delete(_key('pending',state))
  oauth=BasecampOAuth(client_id=os.environ.get('BASECAMP_MULTIUSER_CLIENT_ID',os.environ['BASECAMP_CLIENT_ID']),client_secret=os.environ.get('BASECAMP_MULTIUSER_CLIENT_SECRET',os.environ['BASECAMP_CLIENT_SECRET']),redirect_uri=self.callback_url,user_agent=os.environ['USER_AGENT'])
  tokens=await asyncio.to_thread(oauth.exchange_code_for_token,code); ident=await asyncio.to_thread(oauth.get_identity,tokens['access_token'])
  account=next((a for a in ident.get('accounts',[]) if a.get('product')=='bc3'),None)
  if not account: return HTMLResponse('This Basecamp account has no Basecamp 3 access.',400)
  subject=str(ident['identity']['id'])
  await self.kv.set(_key('basecamp',subject),{'token':self._crypt({'access_token':tokens['access_token'],'refresh_token':tokens['refresh_token'],'account_id':str(account['id']),'expires_at':time.time()+int(tokens.get('expires_in',1209600))})})
  auth_code=secrets.token_urlsafe(32)
  await self.kv.set(_key('code',auth_code),{**pending,'subject':subject},TTL_CODE)
  return RedirectResponse(construct_redirect_uri(pending['redirect_uri'],code=auth_code,state=pending.get('client_state')),302)
 async def load_authorization_code(self,client,code):
  d=await self.kv.get(_key('code',code));
  return AuthorizationCode(code=code,scopes=d['scopes'],expires_at=time.time()+TTL_CODE,client_id=d['client_id'],code_challenge=d['challenge'],redirect_uri=d['redirect_uri'],redirect_uri_provided_explicitly=d['explicit'],resource=d.get('resource'),subject=d['subject']) if d else None
 async def _issue(self,subject,client,scopes,resource=None):
  access=secrets.token_urlsafe(32); refresh=secrets.token_urlsafe(32)
  await self.kv.set(_key('access',access),{'client_id':client.client_id,'scopes':scopes,'subject':subject,'resource':resource},ACCESS_TTL)
  await self.kv.set(_key('refresh',refresh),{'client_id':client.client_id,'scopes':scopes,'subject':subject},REFRESH_TTL)
  return OAuthToken(access_token=access,expires_in=ACCESS_TTL,refresh_token=refresh,scope=' '.join(scopes))
 async def exchange_authorization_code(self,client,code):
  await self.kv.delete(_key('code',code.code)); return await self._issue(code.subject,client,code.scopes,code.resource)
 async def load_refresh_token(self,client,token):
  d=await self.kv.get(_key('refresh',token)); return RefreshToken(token=token,client_id=d['client_id'],scopes=d['scopes'],subject=d['subject']) if d else None
 async def exchange_refresh_token(self,client,token,scopes):
  await self.kv.delete(_key('refresh',token.token)); return await self._issue(token.subject,client,scopes)
 async def load_access_token(self,token):
  d=await self.kv.get(_key('access',token)); return AccessToken(token=token,client_id=d['client_id'],scopes=d['scopes'],subject=d['subject'],resource=d.get('resource')) if d else None
 async def revoke_token(self,token): await self.kv.delete(_key('access' if isinstance(token,AccessToken) else 'refresh',token.token))
 async def basecamp_token(self,subject):
  d=await self.kv.get(_key('basecamp',subject))
  if not d: return None
  token=self._decrypt(d['token'])
  if token.get('expires_at', 0) <= time.time()+300:
   oauth=BasecampOAuth(client_id=os.environ.get('BASECAMP_MULTIUSER_CLIENT_ID',os.environ['BASECAMP_CLIENT_ID']),client_secret=os.environ.get('BASECAMP_MULTIUSER_CLIENT_SECRET',os.environ['BASECAMP_CLIENT_SECRET']),redirect_uri=self.callback_url,user_agent=os.environ['USER_AGENT'])
   fresh=await asyncio.to_thread(oauth.refresh_token,token['refresh_token'])
   token.update(access_token=fresh['access_token'],refresh_token=fresh.get('refresh_token',token['refresh_token']),expires_at=time.time()+int(fresh.get('expires_in',1209600)))
   await self.kv.set(_key('basecamp',subject),{'token':self._crypt(token)})
  return token
