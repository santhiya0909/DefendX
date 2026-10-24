from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import engine, Base, AsyncSessionLocal
from app.core.seeder import seed_initial_data

# Import API routers
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.red_team import router as red_team_router
from app.api.blue_team import router as blue_team_router
from app.api.evaluation import router as evaluation_router
from app.api.comparisons import router as comparisons_router
from app.api.leakage import router as leakage_router
from app.api.isolation_demo import router as isolation_demo_router
from app.api.files import router as files_router
from app.api.findings import router as findings_router
from app.api.evidence import router as evidence_router
from app.api.audit import router as audit_router
from app.api.infrastructure import router as infrastructure_router
from app.api.dashboard import router as dashboard_router
from app.api.chat import router as chat_router
from app.api.reports import router as reports_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables and seed default data
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    async with AsyncSessionLocal() as session:
        await seed_initial_data(session)

    yield
    # Shutdown
    await engine.dispose()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Securing Adversarial AI – Safety Testing Infrastructure with Red/Blue Team Isolation and Cryptographic Audit",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Routers
api_prefix = settings.API_V1_STR
app.include_router(auth_router, prefix=api_prefix)
app.include_router(users_router, prefix=api_prefix)
app.include_router(red_team_router, prefix=api_prefix)
app.include_router(blue_team_router, prefix=api_prefix)
app.include_router(evaluation_router, prefix=api_prefix)
app.include_router(comparisons_router, prefix=api_prefix)
app.include_router(leakage_router, prefix=api_prefix)
app.include_router(isolation_demo_router, prefix=api_prefix)
app.include_router(files_router, prefix=api_prefix)
app.include_router(findings_router, prefix=api_prefix)
app.include_router(evidence_router, prefix=api_prefix)
app.include_router(audit_router, prefix=api_prefix)
app.include_router(infrastructure_router, prefix=api_prefix)
app.include_router(dashboard_router, prefix=api_prefix)
app.include_router(chat_router, prefix=api_prefix)
app.include_router(reports_router, prefix=api_prefix)

@app.get("/")
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "ONLINE",
        "docs": "/docs",
        "api_v1": settings.API_V1_STR
    }

@app.get("/health")
async def health_check():
    return {"status": "HEALTHY", "service": "DefendX Backend API"}
