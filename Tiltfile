ci_settings(timeout='10m', readiness_timeout='3m')

config.define_string('config-file')
config.define_string('dev-vars')
cfg = config.parse()
_is_ci = config.tilt_subcommand == 'ci'
config_file = cfg.get('config-file', 'tests/configs/default.py')
dev_vars_file = cfg.get('dev-vars', 'tests/configs/dev-vars-with-token')
_sha = os.getenv('GITHUB_SHA', '')
default_worker_image = 'k3d-doh-registry:5001/doh-worker' + (':' + _sha if _is_ci and _sha else '')
worker_image = os.getenv('WORKER_IMAGE', default_worker_image)
def with_worker_image(path):
    return blob(str(read_file(path)).replace(
        'image: k3d-doh-registry:5001/doh-worker',
        'image: ' + worker_image,
    ))

worker_yaml = with_worker_image('k8s/worker.yaml')
tests_yaml = with_worker_image('k8s/tests.yaml')

if not (_is_ci and os.getenv('SKIP_DOCKER_BUILD', '') == '1'):
    docker_build(
        worker_image,
        '.',
        ignore=['k8s/', 'nginx/', 'docs/'],
        live_update=[
            sync('src/', '/usr/src/app/src/'),
        ],
    )

watch_file(config_file)
k8s_yaml(local(
    'kubectl create configmap worker-config' +
    ' --from-file=config.py=' + config_file +
    ' --dry-run=client -o yaml',
    quiet=True,
))

watch_file(dev_vars_file)
k8s_yaml(local(
    'kubectl create configmap worker-dev-vars' +
    ' --from-file=.dev.vars=' + dev_vars_file +
    ' --dry-run=client -o yaml',
    quiet=True,
))

# Parse dev-vars file into a ConfigMap of env vars for the test job
k8s_yaml(local(
    'kubectl create configmap worker-dev-vars-env' +
    ' --from-env-file=' + dev_vars_file +
    ' --dry-run=client -o yaml',
    quiet=True,
))

k8s_yaml(['k8s/nginx-config.yaml', 'k8s/nginx.yaml'])
k8s_yaml(worker_yaml)
k8s_yaml(tests_yaml)

k8s_resource('worker', labels=['app'])
k8s_resource('nginx',  labels=['app'], resource_deps=['worker'])

if not _is_ci:
    local_resource(
        'worker-config-restart',
        cmd='kubectl rollout restart deployment/worker',
        deps=['src/config.py'],
        resource_deps=['worker'],
        labels=['app'],
    )

k8s_resource(
    'tests',
    labels=['test'],
    resource_deps=['nginx'],
    auto_init=_is_ci,
    trigger_mode=TRIGGER_MODE_AUTO if _is_ci else TRIGGER_MODE_MANUAL,
)
