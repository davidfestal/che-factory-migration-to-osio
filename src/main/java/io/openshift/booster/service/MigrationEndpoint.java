/*
 * Copyright 2016-2017 Red Hat, Inc, and individual contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.openshift.booster.service;

import java.util.stream.Collectors;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.jsonwebtoken.Jwts;

import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;

@Path("/")
@Component
public class MigrationEndpoint {
    private static final Map<String, String> DOCKERFILE_TO_DOCKERIMAGE = new HashMap<>();
    private static final Map<String, String> OLD_TO_NEW_IMAGES = new HashMap<>();
    
    private RestTemplate template = new RestTemplate();
    private ObjectMapper mapper = new ObjectMapper();
    
    static {
        /*
        FROM codenvy/meteor
        EXPOSE 3000
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipe2rfk03tsdelh7puy/script", 
            "codenvy/meteor");

        /*
        FROM codenvy/cpp_gcc
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/reciperdl04ox9jl2ioge7/script",
            "codenvy/cpp_gcc");

        /*
        FROM stour/cfpio-factory
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/stour/00ae467b303127480813047a6953484f/raw/7d091ca6e565dc4854babd79250f6fef1651bbd7/Dockerfile",
            "codenvy/cpp_gcc");
        
        /*
        FROM florentbenoit/cdvy-ela-23
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/benoitf/b10e9e18fea2e78adedf92cdb196d7c7/raw/6d1444813eb32ddab96a5cbeff471d904b989d25/gistfile1.txt",
            "florentbenoit/cdvy-ela-23");
        
        /*
        FROM codenvy/node
        EXPOSE 8080
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/stour/5a6e80b7fee73a37593ec7baeb95bc69/raw/48228f7a7c630b39c588d7d7ffbb785812708202/Dockerfile",
            "codenvy/node");
        
        /*
        FROM codenvy/node
        EXPOSE 35000
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/stour/d00e07709d1099253ebc5ca71ea1ecd3/raw/7b34b842db570e0b9011e76f6c3c82745adfb3d3/CNRS%2520ISTEX%2520fake%2520recipe",
            "codenvy/node");
        
        /*
        FROM codenvy/ubuntu_gradle
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipe21erxaydy9nnlduc/script",
            "codenvy/ubuntu_gradle");
        
        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipega4hxep75ipg04yo/script",
            "FROM codenvy/ubuntu_jdk8");
        
        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://dockerfiles.codenvycorp.com/templates-4.0/factory/factory-dockerfile",
            "codenvy/ubuntu_jdk8");
        
        /*
        FROM codenvy/node
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipedjt2e75mpeb4cjtc/script",
            "codenvy/node");
        
        /*
        FROM codenvy/php
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipehfmfy5re4n6l2a9u/script",
            "codenvy/php");
        
        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipe7awzx4jnggo2j2fz/script",
            "codenvy/ubuntu_jdk8");
        
        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipeadapc5patzwo0vrd/script",
            "codenvy/ubuntu_jdk8");
        
        /*
        FROM tomitribe/ubuntu_tomee_173_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipehxhkb8daopch2roz/script",
            "tomitribe/ubuntu_tomee_173_jdk8");
        
        /*
        FROM stour/tomee-moviefun-factory
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/stour/44aafac3a2cc215661fd87a705dbd1e9/raw/084e32839c9b64500cd09ec518521644aeb48ca2/Dockerfile",
            "stour/tomee-moviefun-factory");
        
        /*
        FROM stour/tomee-simple-stateless-factory
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "https://gist.githubusercontent.com/stour/89bd5b63a00728098a9a2c7416bf31ad/raw/651c54317035a5f9afb7a570e0a49184c8e78411/Dockerfile",
            "stour/tomee-simple-stateless-factory");
        
        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipeznglq93wgr4fkem6/script",
            "codenvy/ubuntu_jdk8");

        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipec0v4ta2uz6jok0bn/script",
            "codenvy/ubuntu_jdk8");

        /*
        FROM codenvy/ubuntu_wildfly8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "/recipe/recipeeqw0ltbpxk7ez2vn/script",
            "codenvy/ubuntu_wildfly8");

        /*
        FROM nuxeo/che-workspace:master
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "FROM nuxeo/che-workspace:master",
            "nuxeo/che-workspace:master");

        /*
        FROM codenvy/ubuntu_jdk8
         */
        DOCKERFILE_TO_DOCKERIMAGE.put(
            "FROM codenvy/ubuntu_jdk8",
            "codenvy/ubuntu_jdk8");

        OLD_TO_NEW_IMAGES.put("codenvy/ubuntu_jdk8", "registry.devshift.net/che/centos_jdk8");
        OLD_TO_NEW_IMAGES.put("codenvy/node", "registry.devshift.net/che/centos-nodejs");
    }

    public MigrationEndpoint() {
    }

    @GET
    @Path("/codenvy/ids")
    @Produces("application/json")
    public List<String> listCodenvyFactories() throws Exception {
        return retrieveCodenvyfactories().keySet().stream().collect(Collectors.toList());
    }

    @GET
    @Path("/codenvy/full")
    @Produces("application/json")
    public Map<String, FactoryDescription> retrieveCodenvyfactories() {
        Factories factories = template.getForObject("https://www.eclipse.org/che/getting-started/cloud/scripts/factories.json", Factories.class);
        return factories.factories.stream().collect(Collectors.toMap(f->f.factory.replace("https://codenvy.io/f?id=", ""), f->f));
    }
    
    @GET
    @Path("/codenvy/export/{id}")
    public String retrieveFactoryJson(@PathParam("id") String factoryId) {
        ResponseEntity<String> response = template.getForEntity("https://codenvy.io/api/factory/" + factoryId + "?validate=false", String.class);
        if (response.getStatusCode().is2xxSuccessful()) {
            return response.getBody();
        }
        return null;
    }
    
    @GET
    @Path("/codenvy/find/{name}")
    public String retrieveCodenvyFactoryByName(@PathParam("name") String factoryName) throws Exception {
        for (String codenvyFactoryId : listCodenvyFactories()) {
            String json = retrieveFactoryJson(codenvyFactoryId);
            String name = mapper.readTree(json).get("name").asText();
            if (name != null && name.equals(factoryName)) {
                return json;
            }
        }
        return "[]";
    }
    
    private String transformFactoryJson(String json, String factoryId) {
        String osioFactoryJson = json
        .replaceFirst("\"agents\"(:\\[[^]]+)\\]", "\"installers\"$1,\"com.redhat.oc-login\"]")
        .replaceFirst(",\"org.eclipse.che.ssh\"", "")
        .replaceFirst("(\"recipe\":\\{)\"location\"", "$1\"content\"")
        .replaceAll("(\"previewUrl\":\")http://(\\$\\{server\\.)port\\.(\\d+)\\}([^\"]*\")", "$1$2$3/tcp}$4")
        .replaceFirst("\"servers\":\\{\\}(.*)(\"previewUrl\":\"\\$\\{server\\.(\\d+)/tcp\\}[^\"]*\")", "\"servers\":{\"$3/tcp\":{\"port\":\"$3\",\"protocol\":\"http\"}}$1$2")
        .replaceFirst("(\"previewUrl\":\"\\$\\{server\\.(\\d+)/tcp\\}[^\"]*\")(.*)\"servers\":\\{\\}", "$1$3\"servers\":{\"$2/tcp\":{\"port\":\"$2\",\"protocol\":\"http\"}}")
        .replaceFirst(",\"creator\":\\{[^\\}]+\\}", "")
        .replaceFirst(",\"id\":\"" + factoryId + "\"", "");
        String recipeType = osioFactoryJson.replaceFirst(".*\"recipe\":\\{[^\\}]*\"type\":\"([^\"]+)\"[^\\}]*\\}.*", "$1");
        String recipeContent = osioFactoryJson.replaceFirst(".*\"recipe\":\\{[^\\}]*\"content\":\"([^\"]+)\"[^\\}]*\\}.*", "$1");
        String newRecipe = null;
        if ("dockerfile".equals(recipeType)) {
            if (DOCKERFILE_TO_DOCKERIMAGE.containsKey(recipeContent)) {
                recipeType = "dockerimage";
                recipeContent = DOCKERFILE_TO_DOCKERIMAGE.get(recipeContent);
            } else if (recipeContent.startsWith("http://") || recipeContent.startsWith("https://") || recipeContent.startsWith("/")) {
                if (recipeContent.startsWith("/recipe")) {
                    throw new RuntimeException("recipe 'dockerimage' points to a recipe content not accessible inside the 'codenvy.io' server: " + recipeContent);
                }

                try {
                    String recipeRealContent = (String)template.getForObject(recipeContent, String.class, new Object[0]);
                    throw new RuntimeException("recipe 'dockerimage' points to a recipe at the following URL: " + recipeContent + " with the following content :\n" + recipeRealContent);
                } catch (HttpClientErrorException e) {
                    throw new RuntimeException("recipe 'dockerimage' points to a recipe at the following URL: " + recipeContent + " but its content couldn't be retrieved", e);
                }
            }
        }
        if ("dockerimage".equals(recipeType)) {
            if (OLD_TO_NEW_IMAGES.containsKey(recipeContent)) {
                String newImage = OLD_TO_NEW_IMAGES.get(recipeContent);
                if (newImage != null) {
                    recipeContent = newImage;
                }
            }
            newRecipe = "\"recipe\":{\"content\":\"" + recipeContent + "\",\"type\":\"dockerimage\"}";
            osioFactoryJson = osioFactoryJson.replaceFirst("\"recipe\":\\{[^\\}]*\\}", newRecipe);
        }

        return osioFactoryJson;
    }

    @GET
    @Path("/codenvy/transform/{id}")
    public String produceOsiofactory(@PathParam("id") String factoryId) throws Exception {
        return transformFactoryJson(retrieveFactoryJson(factoryId), factoryId);
    }


    @GET
    @Path("/osio/find/{name}")
    public String retrieveExistingOsioFactoryByName(@PathParam("name") String factoryName, @QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + token);

        try {
            ResponseEntity<String> result = template.exchange(cheApiUrl + "factory/find?name=" + factoryName, HttpMethod.GET, new HttpEntity<String>(headers), String.class);
            return result.getBody();
        } catch (HttpClientErrorException e) {
            return new ObjectMapper().createObjectNode().put("error", e.getStatusCode() + " - " + e.getResponseBodyAsString()).toString();
        }
    }
    
    @GET
    @Path("/osio/existing")
    public String retrieveExistingOsioFactories(@QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        if (token == null) {
            throw new IllegalArgumentException("token should not be null");
        }
        String tokenWithoutSignature = token;
        int lastDot = token.lastIndexOf('.');
        if (lastDot > 0) {
            tokenWithoutSignature = token.substring(0, lastDot + 1);
        }
        String userId = Jwts.parser().parseClaimsJwt(tokenWithoutSignature).getBody().getSubject();
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + token);

        ArrayNode result = mapper.createArrayNode();
        try {
            ResponseEntity<String> rawResult = template.exchange(cheApiUrl + "factory/find?creator.userId=" + userId, HttpMethod.GET, new HttpEntity<String>(headers), String.class);
            for (JsonNode factory : mapper.readTree(rawResult.getBody())) {
                ObjectNode factoryDesc = mapper.createObjectNode();
                factoryDesc.put("osioFactoryId", factory.get("id").asText());
                factoryDesc.put("name", factory.get("name").asText());
                result.add(factoryDesc);
            }
            return result.toString();
        } catch (HttpClientErrorException e) {
            return new ObjectMapper().createObjectNode().put("error", e.getStatusCode() + " - " + e.getResponseBodyAsString()).toString();
        }
    }

    @GET
    @Path("/osio/missing")
    public String retrieveMissingOsioFactories(@QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        
        ArrayNode result = mapper.createArrayNode();
        
        for (String codenvyFactoryId : listCodenvyFactories()) {
            String json = retrieveFactoryJson(codenvyFactoryId);
            String name = mapper.readTree(json).get("name").asText();
            JsonNode osioFactoryNode = mapper.readTree(retrieveExistingOsioFactoryByName(name, token, cheApiUrl));
            if (osioFactoryNode.isArray() && osioFactoryNode.size() > 0) {
                osioFactoryNode = osioFactoryNode.get(0);
            }
            if (! osioFactoryNode.has("name")) {
                ObjectNode factoryDesc = mapper.createObjectNode();
                factoryDesc.put("codenvyFactoryId", codenvyFactoryId);
                factoryDesc.put("name", name);
                result.add(factoryDesc);
            }
        }
        return result.toString();
    }
    
    @DELETE
    @Path("/osio/existing/{id}")
    public String deleteExistingOsioFactory(@PathParam("id") String factoryId, @QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + token);

        try {
            ResponseEntity<String> result = template.exchange(cheApiUrl + "factory/" + factoryId, HttpMethod.DELETE, new HttpEntity<String>(headers), String.class);
            return result.toString();
        } catch (HttpClientErrorException e) {
            return new ObjectMapper().createObjectNode().put("error", e.getStatusCode() + " - " + e.getResponseBodyAsString()).toString();
        }
    }
    

    @GET
    @Path("/migrate/{id}")
    public String migrateOsioFactory(@PathParam("id") String factoryId, @QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        String json = transformFactoryJson(retrieveFactoryJson(factoryId), factoryId);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.add("Authorization", "Bearer " + token);

        try {
            ResponseEntity<String> result = template.exchange(cheApiUrl + "factory", HttpMethod.POST, new HttpEntity<String>(json, headers), String.class);
            return result.getBody();
        } catch (HttpClientErrorException e) {
            return new ObjectMapper().createObjectNode().put("error", e.getStatusCode() + " - " + e.getResponseBodyAsString()).toString();
        }
    }
    
    @GET
    @Path("/migrate")
    public Map<String, JsonNode> migrateOsioFactories(@QueryParam("token") String token, @QueryParam("che-api-url") String cheApiUrl) throws Exception {
        Map<String, FactoryDescription> codenvyFactories = retrieveCodenvyfactories();
        return codenvyFactories.entrySet().stream().map((entry) -> {
            String key = entry.getKey();
            FactoryDescription val = entry.getValue();
            try {
                JsonNode migratedNode = mapper.readTree(migrateOsioFactory(key, token, cheApiUrl));
                if (migratedNode.has("id")) {
                    val.factory = cheApiUrl.replace("/api/", "/f?id=" + migratedNode.get("id").asText());
                    return new AbstractMap.SimpleEntry<String, JsonNode>(key, mapper.readTree(mapper.writeValueAsString(val)));
                } else {
                    // error
                    return new AbstractMap.SimpleEntry<String, JsonNode>(key, migratedNode);
                }
            } catch(Exception e) {
                return new AbstractMap.SimpleEntry<String, JsonNode>(key, new ObjectMapper().createObjectNode().put("error", e.toString()));
            }
        }).collect(Collectors.toMap(AbstractMap.SimpleEntry<String, JsonNode>::getKey, AbstractMap.SimpleEntry<String, JsonNode>::getValue));
    }
}


