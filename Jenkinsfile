pipeline {
    agent any

    environment {
        IMAGE_NAME   = 'secure-app'
        IMAGE_TAG    = "${env.BUILD_NUMBER}"
        REGISTRY     = 'registry.example.com'
        FULL_IMAGE   = "${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Docker Image') {
            steps {
                sh "docker build -t ${FULL_IMAGE} ./app"
            }
        }

        stage('Trivy Scan') {
            steps {
                sh """
                    trivy image \
                        --format json \
                        --output reports/scan.json \
                        ${FULL_IMAGE}
                """
            }
        }

        stage('Install SecureGate') {
            steps {
                sh 'python -m pip install -e .'
            }
        }

        stage('SecureGate Evaluate') {
            steps {
                sh """
                    securegate evaluate \
                        reports/scan.json \
                        --policy config/policy.json \
                        --json-output reports/securegate-report.json
                """
            }
        }

        stage('SecureGate K8s Inspect') {
            steps {
                sh """
                    securegate inspect \
                        k8s/ \
                        --policy config/policy.json \
                        --json-output reports/k8s-report.json
                """
            }
        }

        stage('SecureGate Combined Assess') {
            steps {
                sh """
                    securegate assess \
                        reports/scan.json \
                        k8s/ \
                        --policy config/policy.json \
                        --json-output reports/assessment-report.json
                """
            }
        }

        stage('Push to Registry') {
            when {
                expression {
                    return currentBuild.result == null || currentBuild.result == 'SUCCESS'
                }
            }
            steps {
                sh "docker push ${FULL_IMAGE}"
            }
        }

        stage('Deploy to Kubernetes') {
            when {
                branch 'main'
            }
            steps {
                sh "kubectl apply -f k8s/"
            }
        }

        stage('SecureGate Baseline') {
            when {
                branch 'main'
            }
            steps {
                sh """
                    securegate baseline \
                        k8s/ \
                        --policy config/policy.json \
                        --output baselines/security-baseline.json
                """
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**/*.json', allowEmptyArchive: true
        }
        failure {
            echo 'SecureGate security gate BLOCKED the deployment.'
        }
        success {
            echo 'SecureGate security gate PASSED.'
        }
    }
}
