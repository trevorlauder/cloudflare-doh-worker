ci_settings(timeout = "10m", readiness_timeout = "3m")

is_ci = config.tilt_subcommand == "ci"
github_sha = os.getenv("GITHUB_SHA", "")
default_image = "k3d-doh-registry:5001/doh-worker" + (":" + github_sha if is_ci and github_sha else "")
worker_image = os.getenv("WORKER_IMAGE", default_image)

CONFIGS = [
    ("default", "tests/configs/default.py", "tests/configs/dev-vars-with-token"),
    ("no-ecs-no-rebind", "tests/configs/no_ecs_no_rebind.py", "tests/configs/dev-vars-with-token"),
    ("no-token", "tests/configs/default.py", "tests/configs/dev-vars-no-token"),
    ("ecs-mock", "tests/configs/ecs_mock.py", "tests/configs/dev-vars-with-token"),
]

if not (is_ci and os.getenv("SKIP_DOCKER_BUILD", "") == "1"):
    docker_build(
        worker_image,
        ".",
        ignore = ["k8s/", "nginx/", "docs/", "**/__pycache__"],
        live_update = [sync("src/", "/usr/src/app/src/")],
    )

worker_yaml_template = str(read_file("k8s/worker.yaml"))
tests_yaml_template = str(read_file("k8s/tests.yaml"))

def make_worker_yaml(n):
    return (worker_yaml_template
        .replace("image: k3d-doh-registry:5001/doh-worker", "image: " + worker_image)
        .replace("app: worker", "app: worker-" + n)
        .replace("name: worker", "name: worker-" + n))

def make_tests_yaml(n):
    return (tests_yaml_template
        .replace("image: k3d-doh-registry:5001/doh-worker", "image: " + worker_image)
        .replace("name: tests", "name: tests-" + n)
        .replace("value: https://nginx", "value: https://nginx/test-" + n)
        .replace("name: worker", "name: worker-" + n))

def configmap(name, flags):
    return local("kubectl create configmap " + name + flags + " --dry-run=client -o yaml", quiet = True)

k8s_yaml(["k8s/nginx-config.yaml"])

local(
    "openssl req -x509 -newkey rsa:2048 -nodes -days 3650" +
    " -keyout /tmp/doh-nginx-tls.key -out /tmp/doh-nginx-tls.crt" +
    ' -subj "/CN=nginx"' +
    ' -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:nginx"' +
    " 2>/dev/null",
)

k8s_yaml(local(
    "kubectl create secret tls nginx-tls" +
    " --cert=/tmp/doh-nginx-tls.crt --key=/tmp/doh-nginx-tls.key" +
    " --dry-run=client -o yaml",
    quiet = True,
))

k8s_yaml(local(
    "kubectl create configmap nginx-ca" +
    " --from-file=ca.crt=/tmp/doh-nginx-tls.crt" +
    " --dry-run=client -o yaml",
    quiet = True,
))

k8s_yaml(["k8s/nginx.yaml"])

mock_doh_yaml = str(read_file("k8s/mock-doh.yaml")).replace(
    "image: k3d-doh-registry:5001/doh-worker",
    "image: " + worker_image,
)
k8s_yaml(blob(mock_doh_yaml))
k8s_resource("mock-doh", labels = ["app"])

worker_resource_names = []

for (worker_name, config_file, dev_vars_file) in CONFIGS:
    watch_file(config_file)
    watch_file(dev_vars_file)

    k8s_yaml(configmap("worker-" + worker_name + "-config", " --from-file=config.py=" + config_file))
    k8s_yaml(configmap("worker-" + worker_name + "-dev-vars", " --from-file=.dev.vars=" + dev_vars_file))
    k8s_yaml(configmap("worker-" + worker_name + "-dev-vars-env", " --from-env-file=" + dev_vars_file))

    k8s_yaml(blob(make_worker_yaml(worker_name)))
    k8s_yaml(blob(make_tests_yaml(worker_name)))

    worker_resource_names.append("worker-" + worker_name)
    k8s_resource("worker-" + worker_name, labels = ["app"])

k8s_resource("nginx", labels = ["app"], resource_deps = worker_resource_names + ["mock-doh"])

if not is_ci:
    for (worker_name, config_file, _) in CONFIGS:
        local_resource(
            "worker-" + worker_name + "-config-restart",
            cmd = "kubectl rollout restart deployment/worker-" + worker_name,
            deps = [config_file],
            resource_deps = ["worker-" + worker_name],
            auto_init = False,
            labels = ["app"],
        )

test_trigger = TRIGGER_MODE_AUTO if is_ci else TRIGGER_MODE_MANUAL

for (worker_name, _, _) in CONFIGS:
    k8s_resource(
        "tests-" + worker_name,
        labels = ["test"],
        resource_deps = ["nginx"],
        auto_init = is_ci,
        trigger_mode = test_trigger,
    )
