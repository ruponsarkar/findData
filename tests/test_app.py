import importlib
import io
import time

import fitz
import openpyxl
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('LEDGER_DATA_DIR', str(tmp_path))
    import app
    app = importlib.reload(app)
    with TestClient(app.app) as client:
        assert client.post('/api/auth/register',json={'username':'testuser','password':'testing-password'}).status_code == 200
        yield client
    app.POOL.shutdown(wait=True)

def upload(client, name, content):
    response = client.post('/api/documents', files={'files': (name, content)})
    assert response.status_code == 200, response.text
    id = response.json()['documents'][0]['id']
    for _ in range(100):
        data = client.get('/api/dashboard').json()
        document = next(d for d in data['documents'] if d['id'] == id)
        if document['status'] in ('ready', 'error'):
            return id, document, data
        time.sleep(.05)
    pytest.fail('Processing did not finish')

def test_csv_terms_review_export_and_delete(client):
    id, doc, data = upload(client, 'bank.csv', b'Date,Description,Debit,Balance,Currency\n2026-01-01,ACH DEBIT RETURN,35,999,USD\n2026-01-02,OTHER CHARGE,5,994,USD\n')
    assert doc['status'] == 'ready'
    match = data['matches'][0]
    assert match['amount'] == -35
    assert match['columns']['Balance'] == '999'
    assert match['location'] == 'CSV!A2:E2'
    assert data['currencies'] == {'USD':35}
    assert client.patch(f"/api/matches/{match['id']}", json={'reviewed':True}).status_code == 200
    term = client.post('/api/terms', json={'phrase':'OTHER CHARGE'}).json()
    assert len(client.get('/api/dashboard').json()['matches']) == 2
    assert 'OTHER CHARGE' in client.get('/api/export.csv?reviewed=false').text
    assert 'ACH DEBIT RETURN' not in client.get('/api/export.csv?reviewed=false').text
    client.patch(f"/api/terms/{term['id']}", json={'enabled':False})
    assert len(client.get('/api/dashboard').json()['matches']) == 1
    client.delete(f'/api/documents/{id}')
    assert client.get('/api/dashboard').json()['matches'] == []

def test_xlsx_full_row_and_deduplicated_totals(client):
    book = openpyxl.Workbook()
    sheet = book.active
    sheet.title = 'Account'
    sheet.append(['Date','Description','Debit','Currency','Reference'])
    sheet.append(['2026-01-01','ACH DEBIT RETURN SERVICE CHARGE',7,'INR','ABC-123'])
    file = io.BytesIO()
    book.save(file)
    _, doc, data = upload(client, 'bank.xlsx',file.getvalue())
    assert doc['status'] == 'ready'
    assert len(data['matches']) == 2
    assert data['currencies'] == {'INR':7}
    assert data['matches'][0]['columns']['Reference'] == 'ABC-123'
    assert data['matches'][0]['sheet'] == 'Account'

def test_pdf_page_coordinates_and_no_invented_amount(client):
    pdf = fitz.open()
    pdf.new_page().insert_text((70,100),'Welcome')
    pdf.new_page().insert_text((70,100),'ACH DEBIT RETURN 35.00 999.00')
    _, doc, data = upload(client,'bank.pdf',pdf.tobytes())
    assert doc['status'] == 'ready', doc
    match = data['matches'][0]
    assert match['page'] == 2
    assert len(match['bbox']) == 4
    assert match['amount'] is None

def test_validation_and_failed_file(client):
    assert client.post('/api/terms',json={'phrase':'  '}).status_code == 422
    assert client.post('/api/terms',json={'phrase':'ach debit return'}).status_code == 409
    assert client.post('/api/documents',files={'files':('script.exe',b'bad')}).status_code == 400
    _, doc, data = upload(client,'broken.pdf',b'not a PDF')
    assert doc['status'] == 'error'
    assert doc['error']
    assert not data['matches']

def test_phrase_boundaries_and_money():
    from app import matches_phrase, money
    assert matches_phrase('ach   debit RETURN', 'ACH DEBIT RETURN')
    assert not matches_phrase('ACH DEBIT RETURNED', 'ACH DEBIT RETURN')
    assert money('(1,200.50)') == -1200.5
    assert money('NaN') is None

def test_ui_assets_are_served(client):
    assert client.get('/').status_code == 200
    assert 'text/css' in client.get('/static/styles.css').headers['content-type']
    script = client.get('/static/app.js')
    assert script.status_code == 200
    assert 'function renderMatches' in script.text

def wait_document(client, id):
    for _ in range(100):
        data = client.get('/api/dashboard').json()
        doc = next(d for d in data['documents'] if d['id'] == id)
        if doc['status'] not in ('queued', 'processing'):
            return doc, data
        time.sleep(.05)
    pytest.fail('Processing did not finish')

@pytest.mark.parametrize('kind', ['pdf', 'xlsx'])
def test_password_retry_and_upload(client, kind):
    secret = ' test-password-123 '
    if kind == 'pdf':
        pdf = fitz.open()
        pdf.new_page().insert_text((70,100),'ACH DEBIT RETURN')
        content = pdf.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw='owner', user_pw=secret)
    else:
        from msoffcrypto.format.ooxml import OOXMLFile
        book = openpyxl.Workbook()
        book.active.append(['Description', 'Debit'])
        book.active.append(['ACH DEBIT RETURN', 35])
        plain = io.BytesIO()
        book.save(plain)
        plain.seek(0)
        encrypted = io.BytesIO()
        OOXMLFile(plain).encrypt(secret, encrypted)
        content = encrypted.getvalue()
    result = client.post('/api/documents', files={'files':(f'locked.{kind}',content)})
    id = result.json()['documents'][0]['id']
    doc, data = wait_document(client,id)
    assert doc['status'] == 'password_required', doc
    assert not data['matches']
    client.post(f'/api/documents/{id}/retry',json={'password':'wrong'})
    doc, _ = wait_document(client,id)
    assert doc['status'] == 'password_required'
    assert 'Incorrect password' in doc['error']
    client.post(f'/api/documents/{id}/retry',json={'password':secret})
    doc, data = wait_document(client,id)
    assert doc['status'] == 'ready', doc
    assert len(data['matches']) == 1
    assert secret not in str(data)
    assert client.get(f'/api/documents/{id}/file').content == content
    result = client.post('/api/documents', files={'files':(f'locked-upload.{kind}',content)}, data={'password':secret})
    doc, data = wait_document(client,result.json()['documents'][0]['id'])
    assert doc['status'] == 'ready', doc

def test_saved_password_preview_retry_and_forget(client):
    import app
    secret = 'saved-per-file'
    pdf = fitz.open()
    pdf.new_page().insert_text((70,100),'ACH DEBIT RETURN')
    content = pdf.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw='owner', user_pw=secret)
    result = client.post('/api/documents',files={'files':('saved.pdf',content)},data={'password':secret})
    id = result.json()['documents'][0]['id']
    doc, _ = wait_document(client,id)
    assert doc['has_password'] == 1
    with app.db() as c:
        token = c.execute('SELECT password_token FROM documents WHERE id=?',(id,)).fetchone()[0]
    assert secret not in token
    app.init_db()  # Key and token survive app initialization.
    preview = client.get(f'/api/documents/{id}/preview')
    assert preview.status_code == 200
    assert preview.headers['cache-control'] == 'no-store'
    with fitz.open(stream=preview.content, filetype='pdf') as opened:
        assert not opened.needs_pass
        assert 'ACH DEBIT RETURN' in opened[0].get_text()
    assert client.get(f'/api/documents/{id}/file').content == content
    client.post(f'/api/documents/{id}/retry')
    doc,_ = wait_document(client,id)
    assert doc['status'] == 'ready'
    client.delete(f'/api/documents/{id}/password')
    assert client.get(f'/api/documents/{id}/preview').status_code == 409
    client.post(f'/api/documents/{id}/retry')
    doc,_ = wait_document(client,id)
    assert doc['status'] == 'password_required'

def test_bulk_review_and_keyword_management(client):
    _,_,data=upload(client,'bulk.csv',b'Description,Debit\nACH DEBIT RETURN,5\nSERVICE CHARGE,7\nOVERDRAFT FEE,8\n')
    ids=[m['id'] for m in data['matches']]
    assert client.post('/api/matches/review',json={'ids':ids[:2]}).json()['updated']==2
    data=client.get('/api/dashboard').json()
    assert data['stats']['unreviewed']==1
    assert len(data['matches'])==3
    assert client.post('/api/matches/review',json={'ids':[ids[2],999999]}).status_code==409
    assert client.get('/api/dashboard').json()['stats']['unreviewed']==1
    term=next(t for t in data['terms'] if t['phrase']=='ACH DEBIT RETURN')
    client.patch(f"/api/terms/{term['id']}",json={'phrase':term['phrase']})
    assert client.get('/api/dashboard').json()['stats']['unreviewed']==1
    client.patch(f"/api/terms/{term['id']}",json={'phrase':'SERVICE'})
    assert any(m['term']=='SERVICE' for m in client.get('/api/dashboard').json()['matches'])
    client.delete(f"/api/terms/{term['id']}")
    assert all(m['term']!='SERVICE' for m in client.get('/api/dashboard').json()['matches'])
    assert 'value="false" selected' in client.get('/').text

def test_login_persistence_logout_and_expiry(client):
    import app
    token=client.cookies.get('ledger_session')
    assert token
    app.init_db()
    assert client.get('/api/auth/me').json()['username']=='testuser'
    with app.db() as c:
        account=c.execute('SELECT password_hash FROM users').fetchone()[0]
        assert 'testing-password' not in account
        assert c.execute('SELECT token_hash FROM sessions').fetchone()[0]!=token
    assert client.post('/api/auth/logout').status_code==200
    assert client.get('/api/dashboard').status_code==401
    client.cookies.set('ledger_session',token)
    assert client.get('/api/dashboard').status_code==401
    client.cookies.clear()
    assert client.post('/api/auth/login',json={'username':'testuser','password':'wrong-password'}).status_code==401
    result=client.post('/api/auth/login',json={'username':'TESTUSER','password':'testing-password'})
    assert result.status_code==200
    assert 'HttpOnly' in result.headers['set-cookie']
    assert 'Max-Age=2592000' in result.headers['set-cookie']
    with app.db() as c:
        c.execute('UPDATE sessions SET expires_at=0')
    assert client.get('/api/dashboard').status_code==401

def test_users_are_isolated(client):
    import app
    id,_,data=upload(client,'private.csv',b'Description,Debit\nACH DEBIT RETURN,5\n')
    match=data['matches'][0]['id']
    term=data['terms'][0]['id']
    with TestClient(app.app) as other:
        assert other.get(f'/api/documents/{id}/file').status_code==401
        assert other.post('/api/auth/register',json={'username':'another','password':'another-password'}).status_code==200
        assert other.get('/api/dashboard').json()['documents']==[]
        assert other.get('/api/dashboard').json()['matches']==[]
        assert 'private.csv' not in other.get('/api/export.csv').text
        for route in ('file','preview'):
            assert other.get(f'/api/documents/{id}/{route}').status_code==404
        assert other.post(f'/api/documents/{id}/retry').status_code==404
        assert other.delete(f'/api/documents/{id}/password').status_code==404
        assert other.delete(f'/api/documents/{id}').status_code==404
        assert other.patch(f'/api/matches/{match}',json={'reviewed':True}).status_code==404
        assert other.post('/api/matches/review',json={'ids':[match]}).status_code==409
        assert other.patch(f'/api/terms/{term}',json={'phrase':'stolen'}).status_code==404
        other.delete(f'/api/terms/{term}')
        assert len(other.get('/api/terms').json())==4
        assert other.post('/api/terms',json={'phrase':'CUSTOM'}).status_code==200
        assert client.post('/api/terms',json={'phrase':'CUSTOM'}).status_code==200
        upload(other,'other.csv',b'Description,Debit\nCUSTOM,2\n')
    assert len(client.get('/api/dashboard').json()['documents'])==1
    assert client.get('/api/dashboard').json()['matches'][0]['reviewed'] is False
    assert any(t['id']==term for t in client.get('/api/terms').json())

def test_cross_origin_mutations_and_rate_limit(client):
    assert client.post('/api/demo',headers={'Origin':'https://evil.example'}).status_code==403
    assert client.post('/api/auth/login',headers={'Sec-Fetch-Site':'cross-site'},json={'username':'testuser','password':'testing-password'}).status_code==403
    for _ in range(19):
        assert client.post('/api/auth/login',json={'username':'nobody','password':'incorrect-password'}).status_code==401
    assert client.post('/api/auth/login',json={'username':'nobody','password':'incorrect-password'}).status_code==429

def test_legacy_workspace_migration(tmp_path,monkeypatch):
    import sqlite3
    monkeypatch.setenv('LEDGER_DATA_DIR',str(tmp_path))
    c=sqlite3.connect(tmp_path/'ledger.sqlite3')
    c.executescript("""
    CREATE TABLE terms(id INTEGER PRIMARY KEY,phrase TEXT NOT NULL COLLATE NOCASE UNIQUE,enabled INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE documents(id TEXT PRIMARY KEY,name TEXT,path TEXT,size INTEGER,status TEXT,error TEXT,warning TEXT,created_at TEXT,pages INTEGER DEFAULT 0,rows INTEGER DEFAULT 0);
    CREATE TABLE source_rows(id INTEGER PRIMARY KEY,document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,page INTEGER,sheet TEXT,row_number INTEGER,location TEXT,description TEXT,amount REAL,currency TEXT,columns TEXT,bbox TEXT);
    CREATE TABLE matches(id INTEGER PRIMARY KEY,source_id INTEGER REFERENCES source_rows(id) ON DELETE CASCADE,term_id INTEGER REFERENCES terms(id) ON DELETE CASCADE,reviewed INTEGER DEFAULT 0,UNIQUE(source_id,term_id));
    CREATE TABLE initialized(version INTEGER);
    INSERT INTO terms VALUES(1,'LEGACY',1);
    INSERT INTO documents(id,name,status) VALUES('old','Old statement.csv','ready');
    INSERT INTO source_rows(id,document_id,description,columns,bbox) VALUES(1,'old','LEGACY','{}','null');
    INSERT INTO matches VALUES(1,1,1,1);
    """)
    c.commit();c.close()
    import app
    app=importlib.reload(app)
    with TestClient(app.app) as browser:
        assert browser.get('/api/auth/status').json()['setup_required']
        browser.post('/api/auth/register',json={'username':'owner','password':'owner-password'})
        data=browser.get('/api/dashboard').json()
        assert data['documents'][0]['id']=='old'
        assert data['matches'][0]['reviewed'] is True
        assert data['terms'][0]['phrase']=='LEGACY'
        with app.db() as conn:
            assert not conn.execute('PRAGMA foreign_key_check').fetchall()
    app.POOL.shutdown(wait=True)
