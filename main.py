#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenEASD Main Application Entry Point
Automated External Attack Surface Detection for Startups with Lean Security Resources

Company: Cybersecify
Author: Rathnakara G N
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn
from src.core.config_manager import ConfigManager
from src.core.database import DatabaseManager
from src.core.orchestrator import SecurityScanOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="OpenEASD API",
    description="Automated External Attack Surface Detection by Cybersecify",
    version="1.0.0",
    contact={
        "name": "Cybersecify",
        "email": "contact@cybersecify.com",
    },
    license_info={
        "name": "MIT",
    },
)

# Global components
config_manager = None
db_manager = None
orchestrator = None


@app.on_event("startup")
async def startup_event():
    """Initialize OpenEASD components on startup"""
    global config_manager, db_manager, orchestrator
    
    try:
        logger.info("Starting OpenEASD application...")
        
        # Initialize configuration
        config_manager = ConfigManager()
        logger.info("Configuration manager initialized")
        
        # Initialize database
        db_manager = DatabaseManager()
        await db_manager.initialize()
        logger.info("Database manager initialized")
        
        # Initialize orchestrator
        orchestrator = SecurityScanOrchestrator(config_manager, db_manager)
        logger.info("Security scan orchestrator initialized")
        
        logger.info("OpenEASD application started successfully!")
        
    except Exception as e:
        logger.error(f"Failed to start OpenEASD: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global db_manager
    
    try:
        if db_manager:
            await db_manager.close()
        logger.info("OpenEASD application shut down successfully")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "OpenEASD",
        "version": "1.0.0",
        "database": "connected" if db_manager and db_manager.is_connected() else "disconnected"
    }


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Welcome to OpenEASD - Automated External Attack Surface Detection",
        "company": "Cybersecify",
        "author": "Rathnakara G N",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health"
    }


@app.post("/scan/start")
async def start_scan(domain: str, scan_type: str = "full"):
    """Start a security scan for a domain"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not initialized")
        
        # Validate domain
        if not domain or len(domain.strip()) == 0:
            raise HTTPException(status_code=400, detail="Domain is required")
        
        # Start scan
        scan_session = await orchestrator.start_scan(domain.strip(), scan_type)
        
        return {
            "message": f"Scan started for domain: {domain}",
            "session_id": scan_session.id,
            "scan_type": scan_type,
            "status": "initiated"
        }
        
    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{session_id}/status")
async def get_scan_status(session_id: int):
    """Get status of a scan session"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not initialized")
        
        status = await orchestrator.get_scan_status(session_id)
        
        if not status:
            raise HTTPException(status_code=404, detail="Scan session not found")
        
        return status
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/scan/{session_id}/results")
async def get_scan_results(session_id: int):
    """Get results of a scan session"""
    try:
        if not orchestrator:
            raise HTTPException(status_code=503, detail="Orchestrator not initialized")
        
        results = await orchestrator.get_scan_results(session_id)
        
        if not results:
            raise HTTPException(status_code=404, detail="Scan results not found")
        
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


def main():
    """Main entry point"""
    try:
        # Configuration
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        debug = os.getenv("DEBUG", "false").lower() == "true"
        
        logger.info(f"Starting OpenEASD server by Cybersecify on {host}:{port}")
        logger.info("Author: Rathnakara G N")
        logger.info("Company: Cybersecify")
        
        # Run the server
        uvicorn.run(
            "main:app",
            host=host,
            port=port,
            reload=debug,
            log_level="info"
        )
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()