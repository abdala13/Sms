from fastapi import APIRouter
from app.schemas.script import ParseCurlRequest
from app.services.code_generator import CodeGeneratorService
from app.services.curl_parser import CurlParserService
from app.services.dependency_resolver import DependencyResolverService
from app.services.safety_guard import validate_target_url

router = APIRouter(prefix='/api/parser', tags=['parser'])


@router.post('/curl/analyze')
def analyze(req: ParseCurlRequest):
    definition = CurlParserService.parse(req.curl)
    validate_target_url(definition['url'])
    return {'request_definition': definition, 'generated_code': CodeGeneratorService.generate(definition), 'dependencies': DependencyResolverService.detect_from_definition(definition)}
