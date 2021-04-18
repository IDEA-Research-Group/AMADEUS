import ahpy

'''
Ejemplo. Tenemos los siguientes criterios y subcriterios
Nos fijamos en CVE-2009-3555 pero realmente es arbitrario.
Se omiten algunos criterios. Es un ejemplo ilustrativo

apache
- apache-http_server-version
    - apache-http_server-version-2_0_0
    - apache-http_server-version-2_1_0
    - apache-http_server-version-2_2_0
openssl
- openssl-openssl-version
    - openssl-openssl-version_0_9_4
    - openssl-openssl-version_0_9_7b
    - openssl-openssl-version_0_9_8
canonical
- canonical-ubuntu_linux-version
    - canonical-ubuntu_linux-version-10_04
    - canonical-ubuntu_linux-version-12_04
    - canonical-ubuntu_linux-version-13_04
debian
- debian-debian_linux-version
    - debian-debian_linux-version-4_0
    - debian-debian_linux-version-6_0
    - debian-debian_linux-version-8_0
'''

# Criterios raiz. Como de importante es A respecto de B. 1 = misma importancia
criteria_comparisons = {
    ('apache','openssl'): 1/2,
    ('apache','canonical'): 2,
    ('apache','debian'): 2,
    ('openssl','canonical'): 2,
    ('openssl','debian'): 2,
    ('canonical','debian'): 2,
}

apache_version_comparison = {
    ('apache-http_server-version-2_0_0', 'apache-http_server-version-2_1_0'): 1/2,
    ('apache-http_server-version-2_0_0', 'apache-http_server-version-2_2_0'): 1/4,
    ('apache-http_server-version-2_1_0', 'apache-http_server-version-2_2_0'): 1/2
}

openssl_version_comparison = {
    ('openssl-openssl-version_0_9_4', 'openssl-openssl-version_0_9_7b'): 1/2,
    ('openssl-openssl-version_0_9_4', 'openssl-openssl-version_0_9_8'): 1/4,
    ('openssl-openssl-version_0_9_7b', 'openssl-openssl-version_0_9_8'): 1/2
}

ubuntu_version_comparison = {
    ('canonical-ubuntu_linux-version-10_04', 'canonical-ubuntu_linux-version-12_04'): 1/2,
    ('canonical-ubuntu_linux-version-10_04', 'canonical-ubuntu_linux-version-13_04'): 1/4,
    ('canonical-ubuntu_linux-version-12_04', 'canonical-ubuntu_linux-version-13_04'): 1/2
}

debian_version_comparison = {
    ('debian-debian_linux-version-4_0', 'debian-debian_linux-version-6_0'): 1/2,
    ('debian-debian_linux-version-4_0', 'debian-debian_linux-version-8_0'): 1/4,
    ('debian-debian_linux-version-6_0', 'debian-debian_linux-version-8_0'): 1/2
}

root = ahpy.Compare('Criteria',criteria_comparisons, precision=4, random_index='saaty')
apache_version = ahpy.Compare('apache-version', apache_version_comparison, precision=4, random_index='saaty')
openssl_version = ahpy.Compare('openssl-version', openssl_version_comparison, precision=4, random_index='saaty')
ubuntu_version = ahpy.Compare('ubuntu-version', ubuntu_version_comparison, precision=4, random_index='saaty')
debian_version = ahpy.Compare('debian-version', debian_version_comparison, precision=4, random_index='saaty')
apache = ahpy.Compare('apache', {('apache-version','apache-version'):1})
openssl = ahpy.Compare('openssl', {('openssl-version','openssl-version'):1})
ubuntu = ahpy.Compare('canonical', {('ubuntu-version','ubuntu-version'):1})
debian = ahpy.Compare('debian', {('debian-version','debian-version'):1})
root.add_children([apache,openssl,ubuntu,debian])
apache.add_children([apache_version])
openssl.add_children([openssl_version])
ubuntu.add_children([ubuntu_version])
debian.add_children([debian_version])

print("ROOT")
print(root.target_weights)

# Una vez tenemos los target weights, definimos las alternativas
# y las evaluamos para determinar la más apropiada

alt1 = ['openssl-openssl-version_0_9_8','apache-http_server-version-2_0_0','debian-debian_linux-version-6_0']
alt2 = ['openssl-openssl-version_0_9_8','apache-http_server-version-2_0_0','canonical-ubuntu_linux-version-13_04']
alt3 = ['openssl-openssl-version_0_9_4','apache-http_server-version-2_1_0','canonical-ubuntu_linux-version-13_04']

for i, alt in enumerate([alt1,alt2,alt3]):
    tot = sum(1*root.target_weights[attr] for attr in alt)
    print("Alternative {} = {}".format(i+1, tot))

# Los resultados indican que la alternativa 2 es la mas deseable.
