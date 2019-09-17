library identifier: "pipeline-library@v1.1",
retriever: modernSCM(
  [
    $class: "GitSCMSource",
    remote: "https://github.com/redhat-cop/pipeline-library.git"
  ]
)

openshift.withCluster() {

  env.NAMESPACE = openshift.project()
  env.APP_NAME = "calendar-backend"
  env.BUILD = "${env.NAMESPACE}"
  env.DEV = env.BUILD.replace('ci-cd', 'dev')

  env.BUILD_OUTPUT_DIR = env.PIPELINE_CONTEXT_DIR ? "${env.PIPELINE_CONTEXT_DIR}" : "."

  echo "Starting Pipeline for ${APP_NAME}..."

}

pipeline {
  // Use Jenkins Python slave
  // Jenkins will dynamically provision this as OpenShift Pod
  // All the stages and steps of this Pipeline will be executed on this Pod
  // After Pipeline completes the Pod is killed so every run will have clean
  // workspace
  agent {
    label 'jenkins-slave-python'
  }

  // Pipeline Stages start here
  // Requeres at least one stage
  stages {

    // Setup Python with PIPENV and create VENV
    stage('Setup Environment') {

        steps {

            sh """
               set -e
               pip install --user pipenv
               cd "${env.BUILD_OUTPUT_DIR}"
               pipenv sync
               pipenv install --dev
               """

        }

    }

    // Run Dependency Check
    stage('Dependency Check') {

        steps {

            sh "pipenv check"
            // TODO:  Need to validate success

        }

    }

    // Build Container Image using the artifacts produced in previous stages
    stage('Build Container Image'){
      steps {
        binaryBuild(projectName: env.DEV, buildConfigName: env.APP_NAME, artifactsDirectoryName: "${env.BUILD_OUTPUT_DIR}");
      }
    }

    stage('Promote from Build to Dev') {
      steps {
        tagImage(sourceImageName: env.APP_NAME, sourceImagePath: env.DEV, toImagePath: env.DEV)
      }
    }

    //stage ('Verify Deployment to Dev') {
    //  steps {
    //    verifyDeployment(projectName: env.DEV, targetApp: env.APP_NAME)
    //  }
    //}
  }
}
