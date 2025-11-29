"""
Unit tests for the correlation analyzer module.
"""

import pytest
from src.correlation.analyzer import CorrelationEngine


def test_correlation_engine_initialization():
    """Test that correlation engine initializes correctly."""
    engine = CorrelationEngine()
    assert engine is not None
    assert engine.correlations == []
    assert engine.google_results == {}
    assert engine.github_results == {}


def test_calculate_risk_score():
    """Test risk score calculation."""
    engine = CorrelationEngine()
    
    # Test critical severity
    correlation = {
        'type': 'api_endpoint_credential_leak',
        'base_severity': 'critical'
    }
    score = engine.calculate_risk_score(correlation)
    assert 80 <= score <= 100
    
    # Test medium severity
    correlation = {
        'type': 'exposed_file_github_reference',
        'base_severity': 'medium'
    }
    score = engine.calculate_risk_score(correlation)
    assert 30 <= score <= 60


def test_map_risk_to_severity():
    """Test risk score to severity mapping."""
    engine = CorrelationEngine()
    
    assert engine.map_risk_to_severity(95) == 'critical'
    assert engine.map_risk_to_severity(75) == 'high'
    assert engine.map_risk_to_severity(55) == 'medium'
    assert engine.map_risk_to_severity(25) == 'low'


def test_correlate_findings():
    """Test basic correlation functionality."""
    engine = CorrelationEngine()
    
    google_results = {
        'target': 'example.com',
        'categories': {
            'api_endpoints': [
                {
                    'url': 'https://api.example.com',
                    'title': 'API Docs',
                    'category': 'api_endpoints',
                    'severity': 'medium'
                }
            ]
        }
    }
    
    github_results = {
        'target': 'example.com',
        'repositories': [],
        'code_leaks': []
    }
    
    report = engine.correlate_findings(google_results, github_results)
    
    assert 'target' in report
    assert 'correlations' in report
    assert 'risk_summary' in report
    assert 'recommendations' in report
    assert report['target'] == 'example.com'


def test_generate_recommendations():
    """Test recommendation generation."""
    engine = CorrelationEngine()
    
    # Add some test correlations
    engine.correlations = [
        {
            'type': 'api_endpoint_credential_leak',
            'risk_score': 95
        },
        {
            'type': 'database_exposure_credential_leak',
            'risk_score': 90
        }
    ]
    
    recommendations = engine.generate_recommendations()
    
    assert isinstance(recommendations, list)
    assert len(recommendations) > 0
    assert any('API' in rec['title'] for rec in recommendations)


def test_generate_risk_summary():
    """Test risk summary generation."""
    engine = CorrelationEngine()
    
    engine.correlations = [
        {'type': 'api_endpoint_credential_leak', 'severity': 'critical', 'risk_score': 95},
        {'type': 'login_panel_password_leak', 'severity': 'high', 'risk_score': 75},
        {'type': 'exposed_file_github_reference', 'severity': 'medium', 'risk_score': 50}
    ]
    
    summary = engine.generate_risk_summary()
    
    assert summary['total_correlations'] == 3
    assert summary['by_severity']['critical'] == 1
    assert summary['by_severity']['high'] == 1
    assert summary['by_severity']['medium'] == 1
    assert 'average_risk_score' in summary


if __name__ == '__main__':
    pytest.main([__file__])