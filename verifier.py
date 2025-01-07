import os
import pickle
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
import pandas as pd

#”从pem文件中提取特征“
def extract_features_from_pem_file(pem_file_path):
    #从pem文件中提取基本特征，需要的有CN\OU\O\L\S\C\E以及颁发者CN
    with open(pem_file_path, 'rb') as f:
        pem_data = f.read()

    try:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend()) #加载证书

        ##提取主题信息
        subject = cert.subject
        issuer = cert.issuer
        features = {
            'subject.CN':get_attribute(subject, x509.NameOID.COMMON_NAME),
            'subject.OU':get_attribute(subject, x509.NameOID.ORGANIZATIONAL_UNIT_NAME),
            'subject.O':get_attribute(subject, x509.NameOID.ORGANIZATION_NAME),
            'subject.L':get_attribute(subject, x509.NameOID.LOCALITY_NAME),
            'subject.S':get_attribute(subject, x509.NameOID.STATE_OR_PROVINCE_NAME),
            'subject.C':get_attribute(subject, x509.NameOID.COUNTRY_NAME),
            'subject.E':get_attribute(subject, x509.NameOID.EMAIL_ADDRESS),
            'issuer.CN':get_attribute(issuer, x509.NameOID.COMMON_NAME),
        }
    except Exception as e:
        print(f"Error loading certificate from PEM file: {e}") #加载证书失败
        features = {
            'subject.CN':"missing",
            'subject.OU':"missing",
            'subject.O':"missing",
            'subject.S':"missing",
            'subject.C':"missing",
            'subject.E':"missing",
            'issuer.CN':"missing",
        }
    return features

def get_attribute(entity, oid):
    ##定义一种从证书的主题或颁发者中提取指定属性的方法
    try:
        attr = entity.get_attribute_for_oid(oid) #获取属性，具体怎么运行的后续再研究
        return attr[0].value if attr else "missing"
    except AttributeError:
        return "missing"

def load_data(data_dir,label):
    ##加载文件夹目录的所有pem文件或者单个pem文件，并提取其特征
    ##data_dir:文件夹目录或pem文件的绝对路径，label:该目录下文件的标签，1表示恶意，0表示良性
    data = []
    for file_name in os.listdir(data_dir):
        if file_name.endswith('.pem'):
            file_path = os.path.join(data_dir, file_name)
            features = extract_features_from_pem_file(file_path)
            if features:
                features['label'] = label
                data.append(features)
    return data

def main():
    #数据目录
    benign_dir = "C:/Users\wangxiangyu\Desktop\certificates-dataset-for-experiment\legal"
    malicious_dir = "C:/Users\wangxiangyu\Desktop\certificates-dataset-for-experiment\illegal"

    #加载数据
    benign_data = load_data(benign_dir, label=0)
    malicious_data = load_data(malicious_dir, label=1)
    data = pd.DataFrame(benign_data + malicious_data) #将两个数据集合并成一个数据集
    ##处理缺失值
    data.fillna("missing", inplace=True)

    #对分类特征进行one-hot编码
    X = pd.get_dummies(data, columns=['subject.CN', 'subject.OU', 'subject.O', 'subject.L', 'subject.S', 'subject.C', 'subject.E', 'issuer.CN'])
    Y = data['label']

    #划分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)
    #训练随机森林模型
    model = RandomForestClassifier(n_estimators=100, random_state=42) #随机森林分类器
    model.fit(X_train, y_train)

    #测试模型
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))

    #保存模型
    if accuracy_score(y_test, y_pred) > 0.8:
        with open('certificate_verifier.sav', 'wb') as model_file:
            pickle.dump(model, model_file)
        print("Model saved successfully as certificate_verifier.sav.")

if __name__ == '__main__':
    main()