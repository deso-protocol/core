import groovy.transform.Field

pipeline {
    agent { dockerfile true }
    stages {
        stage('vet and test') {
            steps {
                sh 'go vet ./...'
                sh 'go test -v'
            }
        }
    }
}
